/*
 * Copyright: Rui Gomes, all rights reserved.
 * Distributed under MIT .
 * rui.tech@gmail.com 
 *
 * 2025-10-15
 * Full re write with support for python3
 * thread support, and output to json file
 * 
 * 
 * 2012-12-26
 * Major restructer of the code;
 * Add function that return a list 
 * of all the files that error out;
 * Add Inode information to the return;
 *
 * 2012-12-20
 * Code clean up
 *
 * 2012-12-01
 * Add error handling by errno
 * Add positional arguments and keywords
 * Add option to disable crc32 check sum 
 * Return exception if initial directory of path doesnt exist.
 *  <fsdir.erro> exception 
 * Overal code clean up. 
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 2012-01-11
 * Change the function from ftw() to nftw()
 * resolved the problem with global flag not be reseted between calls
 */




#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>

/* -----------------------------------------------------------------------
   Global state
   ----------------------------------------------------------------------- */
static PyObject *g_dir_list    = NULL;
static PyObject *g_errors_list = NULL;
static PyObject *fsdirError    = NULL;

static int g_summary_flag   = 0;
static int g_crc32_flag     = 0;
static int g_resolve_users  = 0;
static int g_measure_time   = 0;
static const char *g_output_path = NULL;

static long g_file_total = 0;
static long g_dir_total  = 0;
static long g_size_total = 0;   /* KiB */

/* -----------------------------------------------------------------------
   UID → username cache (thread-safe)
   ----------------------------------------------------------------------- */
typedef struct user_entry {
    uid_t uid;
    char *name;
    struct user_entry *next;
} user_entry_t;

#define USER_HASH_SIZE 128
static user_entry_t *user_hash[USER_HASH_SIZE];
static pthread_mutex_t user_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *username_from_uid(uid_t uid)
{
    unsigned idx = uid % USER_HASH_SIZE;
    pthread_mutex_lock(&user_cache_lock);
    for (user_entry_t *e = user_hash[idx]; e; e = e->next) {
        if (e->uid == uid) {
            const char *r = e->name;
            pthread_mutex_unlock(&user_cache_lock);
            return r;
        }
    }

    struct passwd pw, *res = NULL;
    char buf[4096];
    if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0 && res && res->pw_name) {
        user_entry_t *ne = (user_entry_t *)malloc(sizeof(*ne));
        if (ne) {
            ne->uid = uid;
            ne->name = strdup(res->pw_name);
            ne->next = user_hash[idx];
            user_hash[idx] = ne;
        }
        pthread_mutex_unlock(&user_cache_lock);
        return res->pw_name;
    }
    pthread_mutex_unlock(&user_cache_lock);
    return "unknown";
}

/* -----------------------------------------------------------------------
   C result & error buffers (thread-safe)
   ----------------------------------------------------------------------- */
typedef struct result_node {
    char *path;
    long size_kb;
    char type;          /* 'F' */
    uid_t owner_uid;
    char permOwner[4], permGroup[4], permOthers[4];
    ino_t inode;
    uint32_t crc32;
    struct result_node *next;
} result_node_t;

typedef struct error_node {
    char *path;
    char *reason;
    struct error_node *next;
} error_node_t;

static struct {
    result_node_t *head, *tail;
    pthread_mutex_t lock;
} g_results = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER };

static struct {
    error_node_t *head, *tail;
    pthread_mutex_t lock;
} g_errors  = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER };

static void results_clear(void)
{
    pthread_mutex_lock(&g_results.lock);
    result_node_t *r = g_results.head; g_results.head = g_results.tail = NULL;
    pthread_mutex_unlock(&g_results.lock);
    while (r) { result_node_t *t = r->next; free(r->path); free(r); r = t; }
}
static void errors_clear(void)
{
    pthread_mutex_lock(&g_errors.lock);
    error_node_t *e = g_errors.head; g_errors.head = g_errors.tail = NULL;
    pthread_mutex_unlock(&g_errors.lock);
    while (e) { error_node_t *t = e->next; free(e->path); free(e->reason); free(e); e = t; }
}

static void errors_push(const char *path, const char *reason)
{
    error_node_t *n = (error_node_t *)malloc(sizeof(*n));
    if (!n) return;
    n->path   = path   ? strdup(path)   : strdup("");
    n->reason = reason ? strdup(reason) : strdup("error");
    n->next = NULL;

    pthread_mutex_lock(&g_errors.lock);
    if (g_errors.tail) g_errors.tail->next = n; else g_errors.head = n;
    g_errors.tail = n;
    pthread_mutex_unlock(&g_errors.lock);
}

/* -----------------------------------------------------------------------
   JSON output (compact array) for streaming mode
   - Used only when summary == false and output_file is provided.
   - Writes directly from worker context (no Python), guarded by a lock.
   ----------------------------------------------------------------------- */
static FILE *json_fp = NULL;
static int json_first = 1;
static pthread_mutex_t json_lock = PTHREAD_MUTEX_INITIALIZER;

static void json_open(const char *path)
{
    json_fp = fopen(path, "w");
    if (json_fp) {
        fputs("[", json_fp);
        fflush(json_fp);
        json_first = 1;
    }
}
static void json_close(void)
{
    if (!json_fp) return;
    fputs("]\n", json_fp);
    fclose(json_fp);
    json_fp = NULL;
}

static void json_write_escaped(FILE *fp, const char *s)
{
    /* Minimal JSON string escape (quotes and backslashes) */
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '\\' || *p == '\"') {
            fputc('\\', fp);
            fputc(*p, fp);
        } else if (*p == '\n') {
            fputs("\\n", fp);
        } else if (*p == '\r') {
            fputs("\\r", fp);
        } else if (*p == '\t') {
            fputs("\\t", fp);
        } else {
            fputc(*p, fp);
        }
    }
}

static void json_write_entry_stream(const result_node_t *r)
{
    if (!json_fp) return;
    pthread_mutex_lock(&json_lock);
    if (!json_first) fputs(",", json_fp); else json_first = 0;
    fputc('{', json_fp);

    /* "Path": "..." */
    fputs("\"Path\":\"", json_fp);
    json_write_escaped(json_fp, r->path ? r->path : "");
    fputs("\",", json_fp);

    /* "Size": N, "Type": "F" */
    fprintf(json_fp, "\"Size\":%ld,\"Type\":\"%c\",", r->size_kb, r->type);

    /* "Owner": username or uid */
    if (g_resolve_users) {
        const char *uname = username_from_uid(r->owner_uid);
        fputs("\"Owner\":\"", json_fp);
        json_write_escaped(json_fp, uname ? uname : "unknown");
        fputs("\",", json_fp);
    } else {
        fprintf(json_fp, "\"Owner\":%lu,", (unsigned long)r->owner_uid);
    }

    /* perms */
    fprintf(json_fp,
            "\"permOwner\":\"%s\",\"permGroup\":\"%s\",\"permOthers\":\"%s\",",
            r->permOwner, r->permGroup, r->permOthers);

    /* inode */
    fprintf(json_fp, "\"Inode\":%lu", (unsigned long)r->inode);

    /* CRC32 if requested */
    if (g_crc32_flag) {
        fprintf(json_fp, ",\"CRC32\":%u", r->crc32);
    }

    fputc('}', json_fp);
    fflush(json_fp);
    pthread_mutex_unlock(&json_lock);
}

static void json_write_elapsed(double seconds)
{
    if (!json_fp) return;
    pthread_mutex_lock(&json_lock);
    if (!json_first) fputs(",", json_fp); else json_first = 0;
    fprintf(json_fp, "{\"ElapsedSeconds\":%.9g}", seconds);
    fflush(json_fp);
    pthread_mutex_unlock(&json_lock);
}

/* -----------------------------------------------------------------------
   Result push: either stream JSON directly (no memory growth), or buffer
   ----------------------------------------------------------------------- */
static void results_push(const result_node_t *src)
{
    if (json_fp && !g_summary_flag) {
        /* streaming mode: write immediately, no buffering */
        json_write_entry_stream(src);
        return;
    }

    /* buffered mode: store in linked list */
    result_node_t *n = (result_node_t *)malloc(sizeof(*n));
    if (!n) return;
    *n = *src;
    n->path = src->path ? strdup(src->path) : NULL;
    n->next = NULL;

    pthread_mutex_lock(&g_results.lock);
    if (g_results.tail) g_results.tail->next = n; else g_results.head = n;
    g_results.tail = n;
    pthread_mutex_unlock(&g_results.lock);
}

/* -----------------------------------------------------------------------
   Build Python outputs from buffered results (non-streaming only)
   ----------------------------------------------------------------------- */
static void build_python_lists_from_buffers(void)
{
    if (!g_summary_flag) {
        pthread_mutex_lock(&g_results.lock);
        for (result_node_t *r = g_results.head; r; r = r->next) {
            PyObject *row = PyDict_New();
            if (!row) continue;
            PyObject *v;

            PyDict_SetItemString(row, "Path", (v = PyUnicode_FromString(r->path ? r->path : ""))); Py_XDECREF(v);
            PyDict_SetItemString(row, "Size", (v = PyLong_FromLong(r->size_kb))); Py_XDECREF(v);
            char tbuf[2] = { r->type, 0 };
            PyDict_SetItemString(row, "Type", (v = PyUnicode_FromString(tbuf))); Py_XDECREF(v);

            if (g_resolve_users) {
                const char *uname = username_from_uid(r->owner_uid);
                PyDict_SetItemString(row, "Owner", (v = PyUnicode_FromString(uname ? uname : "unknown"))); Py_XDECREF(v);
            } else {
                PyDict_SetItemString(row, "Owner", (v = PyLong_FromLong((long)r->owner_uid))); Py_XDECREF(v);
            }

            PyDict_SetItemString(row, "permOwner", (v = PyUnicode_FromString(r->permOwner)));   Py_XDECREF(v);
            PyDict_SetItemString(row, "permGroup", (v = PyUnicode_FromString(r->permGroup)));   Py_XDECREF(v);
            PyDict_SetItemString(row, "permOthers",(v = PyUnicode_FromString(r->permOthers)));  Py_XDECREF(v);
            PyDict_SetItemString(row, "Inode", (v = PyLong_FromUnsignedLong((unsigned long)r->inode))); Py_XDECREF(v);
            if (g_crc32_flag)
                PyDict_SetItemString(row, "CRC32", (v = PyLong_FromUnsignedLong(r->crc32))), Py_XDECREF(v);

            PyList_Append(g_dir_list, row);
            Py_DECREF(row);
        }
        pthread_mutex_unlock(&g_results.lock);
    }

    /* errors -> g_errors_list */
    pthread_mutex_lock(&g_errors.lock);
    for (error_node_t *e = g_errors.head; e; e = e->next) {
        PyObject *pair = Py_BuildValue("[ss]", e->path ? e->path : "", e->reason ? e->reason : "error");
        if (pair) { PyList_Append(g_errors_list, pair); Py_DECREF(pair); }
    }
    pthread_mutex_unlock(&g_errors.lock);
}

/* -----------------------------------------------------------------------
   Work queue (manager waits for drain)
   ----------------------------------------------------------------------- */
typedef struct queue_node { char *path; struct queue_node *next; } queue_node_t;
typedef struct {
    queue_node_t *head, *tail;
    int queued, active, stop;
    pthread_mutex_t lock; pthread_cond_t cond;
} queue_t;

static queue_t work_q;

static void queue_init(queue_t *q)
{
    q->head = q->tail = NULL;
    q->queued = q->active = q->stop = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}
static void queue_destroy(queue_t *q)
{
    queue_node_t *n = q->head;
    while (n) { queue_node_t *t = n->next; free(n->path); free(n); n = t; }
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}
static void queue_push(queue_t *q, const char *p)
{
    queue_node_t *n = (queue_node_t *)malloc(sizeof(*n));
    if (!n) return;
    n->path = strdup(p);
    n->next = NULL;
    pthread_mutex_lock(&q->lock);
    if (q->tail) q->tail->next = n; else q->head = n;
    q->tail = n; q->queued++;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}
static char *queue_pop(queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    for (;;) {
        if (q->stop) { pthread_mutex_unlock(&q->lock); return NULL; }
        if (q->head) {
            queue_node_t *n = q->head; q->head = n->next;
            if (!q->head) q->tail = NULL;
            q->queued--; q->active++;
            char *p = n->path; free(n);
            pthread_mutex_unlock(&q->lock);
            return p;
        }
        pthread_cond_wait(&q->cond, &q->lock);
    }
}
static void queue_done(queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    q->active--;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}
static void queue_manager_wait(queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    while (q->queued > 0 || q->active > 0)
        pthread_cond_wait(&q->cond, &q->lock);
    q->stop = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* -----------------------------------------------------------------------
   CRC32 and perms helpers
   ----------------------------------------------------------------------- */
static uint32_t crc32Digest(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t buf[8192];
    uint32_t crc = crc32(0L, Z_NULL, 0);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        crc = crc32(crc, buf, (uInt)n);
    fclose(f);
    return crc;
}
static void perms(mode_t m, char u[4], char g[4], char o[4])
{
    u[0]=(m&S_IRUSR)?'r':'-'; u[1]=(m&S_IWUSR)?'w':'-'; u[2]=(m&S_IXUSR)?'x':'-'; u[3]=0;
    g[0]=(m&S_IRGRP)?'r':'-'; g[1]=(m&S_IWGRP)?'w':'-'; g[2]=(m&S_IXGRP)?'x':'-'; g[3]=0;
    o[0]=(m&S_IROTH)?'r':'-'; o[1]=(m&S_IWOTH)?'w':'-'; o[2]=(m&S_IXOTH)?'x':'-'; o[3]=0;
}

/* -----------------------------------------------------------------------
   Worker logic (no Python calls)
   ----------------------------------------------------------------------- */
static void process_directory(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) { errors_push(dir, strerror(errno)); return; }

    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

        unsigned char t = de->d_type;
        if (t == DT_UNKNOWN) {
            struct stat ts;
            if (lstat(path, &ts) == 0) {
                if (S_ISDIR(ts.st_mode)) t = DT_DIR;
                else if (S_ISREG(ts.st_mode)) t = DT_REG;
            }
        }

        if (t == DT_DIR) {
            queue_push(&work_q, path);
            __sync_add_and_fetch(&g_dir_total, 1);
            continue;
        }

        if (t == DT_REG) {
            struct stat sb;
            if (lstat(path, &sb) == 0) {
                long sz = (sb.st_blocks * 512) / 1024;
                __sync_add_and_fetch(&g_file_total, 1);
                __sync_add_and_fetch(&g_size_total, sz);

                if (!g_summary_flag) {
                    result_node_t r;
                    memset(&r, 0, sizeof(r));
                    r.path = (char *)path;  /* duplicated if buffering */
                    r.size_kb = sz;
                    r.type = 'F';
                    r.owner_uid = sb.st_uid;
                    r.inode = sb.st_ino;
                    perms(sb.st_mode, r.permOwner, r.permGroup, r.permOthers);
                    r.crc32 = g_crc32_flag ? crc32Digest(path) : 0;
                    results_push(&r);
                }
            } else {
                errors_push(path, strerror(errno));
            }
        }
    }
    closedir(d);
}

static void *worker(void *a)
{
    (void)a;
    for (;;) {
        char *p = queue_pop(&work_q);
        if (!p) break;
        process_directory(p);
        free(p);
        queue_done(&work_q);
    }
    return NULL;
}

/* -----------------------------------------------------------------------
   Python entry
   ----------------------------------------------------------------------- */
static int pathconv(PyObject *o, void *out) { return PyUnicode_FSConverter(o, (PyObject **)out); }

static PyObject *fsdir_go(PyObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"path","summary","crc32","max_threads","resolve_users","measure_time","output_file",NULL};
    PyObject *path_b = NULL;
    int summary=0, crc32=0, max_threads=0, res_users=0, measure_time=0;
    const char *outpath = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "O&|ppiiiz",
                                     kwlist, pathconv, &path_b,
                                     &summary, &crc32, &max_threads,
                                     &res_users, &measure_time, &outpath))
        return NULL;

    g_summary_flag  = summary;
    g_crc32_flag    = crc32;
    g_resolve_users = res_users;
    g_measure_time  = measure_time;
    g_output_path   = outpath;   /* may be NULL */

    struct timespec ts0, ts1;
    if (g_measure_time) clock_gettime(CLOCK_MONOTONIC, &ts0);

    const char *path = PyBytes_AsString(path_b);
    if (!path) { Py_DECREF(path_b); return NULL; }

    struct stat sb;
    if (lstat(path, &sb) != 0) {
        Py_DECREF(path_b);
        PyErr_SetFromErrnoWithFilename(fsdirError, path);
        return NULL;
    }

    Py_XDECREF(g_dir_list);
    Py_XDECREF(g_errors_list);
    g_dir_list    = PyList_New(0);
    g_errors_list = PyList_New(0);

    g_file_total = g_dir_total = g_size_total = 0;
    results_clear();
    errors_clear();
    queue_init(&work_q);

    /* open streaming JSON if requested and not summary */
    if (g_output_path && !g_summary_flag) json_open(g_output_path);

    /* Single file */
    if (S_ISREG(sb.st_mode)) {
        g_file_total++;
        long sz = (sb.st_blocks * 512) / 1024;
        g_size_total += sz;

        if (!g_summary_flag) {
            result_node_t r; memset(&r, 0, sizeof(r));
            r.path = (char *)path; r.size_kb = sz; r.type='F';
            r.owner_uid = sb.st_uid; r.inode = sb.st_ino;
            perms(sb.st_mode, r.permOwner, r.permGroup, r.permOthers);
            r.crc32 = g_crc32_flag ? crc32Digest(path) : 0;
            results_push(&r);
        }
        goto finalize_outputs;
    }

    /* Seed subdirs, process top-level files inline */
    DIR *d = opendir(path);
    if (!d) { errors_push(path, strerror(errno)); goto finalize_outputs; }

    int init_dirs = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);

        unsigned char t = de->d_type;
        if (t == DT_UNKNOWN) {
            struct stat ts;
            if (lstat(child, &ts) == 0) {
                if (S_ISDIR(ts.st_mode)) t = DT_DIR;
                else if (S_ISREG(ts.st_mode)) t = DT_REG;
            }
        }

        if (t == DT_DIR) {
            queue_push(&work_q, child);
            g_dir_total++; init_dirs++;
        } else if (t == DT_REG) {
            struct stat fsb;
            if (lstat(child, &fsb) == 0) {
                g_file_total++;
                long sz = (fsb.st_blocks * 512) / 1024;
                g_size_total += sz;

                if (!g_summary_flag) {
                    result_node_t r; memset(&r, 0, sizeof(r));
                    r.path = (char *)child; r.size_kb = sz; r.type='F';
                    r.owner_uid = fsb.st_uid; r.inode = fsb.st_ino;
                    perms(fsb.st_mode, r.permOwner, r.permGroup, r.permOthers);
                    r.crc32 = g_crc32_flag ? crc32Digest(child) : 0;
                    results_push(&r);
                }
            } else {
                errors_push(child, strerror(errno));
            }
        }
    }
    closedir(d);

    if (init_dirs == 0) goto finalize_outputs;

    /* Determine threads */
    int cpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu < 1) cpu = 1;
    int auto_cap = cpu < 8 ? cpu : 8;
    int desired  = (max_threads > 0) ? max_threads : auto_cap;
    if (desired < 1)  desired = 1;
    int nthreads = (init_dirs < desired) ? init_dirs : desired;
    if (nthreads < 1) nthreads = 1;

    pthread_t *threads = (pthread_t *)calloc(nthreads, sizeof(pthread_t));

    /* Run workers without GIL (no Python calls inside) */
    Py_BEGIN_ALLOW_THREADS
    for (int i = 0; i < nthreads; ++i)
        (void)pthread_create(&threads[i], NULL, worker, NULL);

    queue_manager_wait(&work_q);

    for (int i = 0; i < nthreads; ++i)
        (void)pthread_join(threads[i], NULL);
    Py_END_ALLOW_THREADS

    free(threads);

finalize_outputs:
    /* Convert buffered results to Python if not streaming; errors always */
    if (!(g_output_path && !g_summary_flag))
        build_python_lists_from_buffers();

    /* Timing */
    double elapsed = 0.0;
    if (g_measure_time) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        elapsed = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) / 1e9;
    }

    /* If streaming to file in detailed mode, append ElapsedSeconds to JSON */
    if (g_output_path && !g_summary_flag) {
        if (g_measure_time) json_write_elapsed(elapsed);
        json_close();

        /* Return a tiny metadata dict (so caller knows where to read) */
        PyObject *meta = PyDict_New();
        if (meta) {
            PyObject *v;
            PyDict_SetItemString(meta, "OutputFile", (v = PyUnicode_FromString(g_output_path))); Py_XDECREF(v);
            PyDict_SetItemString(meta, "Dirs",  (v = PyLong_FromLong(g_dir_total)));  Py_XDECREF(v);
            PyDict_SetItemString(meta, "Files", (v = PyLong_FromLong(g_file_total))); Py_XDECREF(v);
            PyDict_SetItemString(meta, "Size",  (v = PyLong_FromLong(g_size_total))); Py_XDECREF(v);
            if (g_measure_time)
                PyDict_SetItemString(meta, "ElapsedSeconds", (v = PyFloat_FromDouble(elapsed))), Py_XDECREF(v);
            PyList_Append(g_dir_list, meta);
            Py_DECREF(meta);
        }
    } else if (g_summary_flag) {
        PyObject *summary_dict = PyDict_New();
        if (summary_dict) {
            PyObject *v;
            PyDict_SetItemString(summary_dict, "Dirs",  (v = PyLong_FromLong(g_dir_total)));  Py_XDECREF(v);
            PyDict_SetItemString(summary_dict, "Files", (v = PyLong_FromLong(g_file_total))); Py_XDECREF(v);
            PyDict_SetItemString(summary_dict, "Size",  (v = PyLong_FromLong(g_size_total))); Py_XDECREF(v);
            if (g_measure_time)
                PyDict_SetItemString(summary_dict, "ElapsedSeconds", (v = PyFloat_FromDouble(elapsed))), Py_XDECREF(v);
            PyList_Append(g_dir_list, summary_dict);
            Py_DECREF(summary_dict);
        }
    } else if (g_measure_time) {
        /* detailed in-memory mode: append elapsed entry */
        PyObject *elapsed_entry = Py_BuildValue("{s:d}", "ElapsedSeconds", elapsed);
        PyList_Append(g_dir_list, elapsed_entry);
        Py_DECREF(elapsed_entry);
    }

    /* Cleanup */
    results_clear();
    errors_clear();
    queue_destroy(&work_q);

    Py_DECREF(path_b);
    Py_INCREF(g_dir_list);
    return g_dir_list;
}

/* -----------------------------------------------------------------------
   fsdir.errors()
   ----------------------------------------------------------------------- */
static PyObject *fsdir_errors(PyObject *self, PyObject *args)
{
    if (!g_errors_list) Py_RETURN_NONE;
    Py_INCREF(g_errors_list);
    return g_errors_list;
}

/* -----------------------------------------------------------------------
   Module definition
   ----------------------------------------------------------------------- */
static PyMethodDef FsdirMethods[] = {
    {"go", (PyCFunction)fsdir_go, METH_VARARGS | METH_KEYWORDS,
     "Traverse filesystem.\n"
     "go(path, summary=False, crc32=False, max_threads=0, "
     "resolve_users=False, measure_time=False, output_file=None) -> list[dict]"},
    {"errors", (PyCFunction)fsdir_errors, METH_NOARGS,
     "Return list of [path, reason] pairs that failed."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef fsdir_module = {
    PyModuleDef_HEAD_INIT,
    "fsdir",
    "Multithreaded scandir traversal (GIL-free workers, username cache, timing, streaming JSON).",
    -1,
    FsdirMethods
};

PyMODINIT_FUNC PyInit_fsdir(void)
{
    PyObject *m = PyModule_Create(&fsdir_module);
    if (!m) return NULL;
    fsdirError = PyErr_NewException("fsdir.error", NULL, NULL);
    Py_INCREF(fsdirError);
    PyModule_AddObject(m, "error", fsdirError);
    if (PyModule_AddStringConstant(m, "__version__", "1.0.0") < 0) {
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
