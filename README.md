# fsdir — Multithreaded Filesystem Scanner for Python

`fsdir` is a **high-performance multithreaded directory traversal module** written in C for Python 3.
It provides safe, GIL-free concurrent scanning of large directory trees, collecting metadata such as file size, permissions, owner, inode, and optional CRC32 checksums — all without blocking Python execution.

It is designed for **HPC**, **media asset indexing**, and **large-scale filesystem analytics**.

---

## 🚀 Features

- **Multithreaded traversal** Threads work without holding the Python GIL.
- **Optional CRC32 checksums** 
- **Optional timing measurements** (`ElapsedSeconds`).
- **Optional streaming JSON output to disk** — for very large scans (no RAM growth).
- **Thread-safe error tracking** (`fsdir.errors()`).
- Fully **Python 3.x compatible**, written in C11.

---

## 📦 Building the Module

```bash
python3 setup.py build_ext --inplace
```

This creates `fsdir.cpython-<ver>-x86_64-linux-gnu.so` in your current directory.

---

## 🧩 Usage

```python
import fsdir
import json

# Basic usage
results = fsdir.go("path/to/scan")
print(json.dumps(results, indent=2))
```

---

## ⚙️ Function Reference

### `fsdir.go(path, summary=False, crc32=False, max_threads=0, resolve_users=False, measure_time=False, output_file=None)`

Scans the directory tree (or a single file) starting from `path`.

### Parameters

| Parameter | Type | Default | Description |
|------------|------|----------|-------------|
| **`path`** | `str` | — | The root directory or file to scan. |
| **`summary`** | `bool` | `False` | If `True`, only returns totals (`Dirs`, `Files`, `Size`, `ElapsedSeconds`). If `False`, returns one dict per file. |
| **`crc32`** | `bool` | `False` | Compute CRC32 checksums for regular files using zlib. |
| **`max_threads`** | `int` | `0` | Maximum number of worker threads (default = auto, no hard cap). |
| **`resolve_users`** | `bool` | `False` | Convert UID → username with internal caching. |
| **`measure_time`** | `bool` | `False` | Measure elapsed wall-clock time and include `"ElapsedSeconds"`. |
| **`output_file`** | `str` or `None` | `None` | If provided and `summary=False`, stream detailed results directly to this file as a compact JSON array. Overwrites each run. |

---

## 📤 Return Values

### 1. When `summary=False` (default)
Returns a **list of dictionaries** (one per file), each containing:

| Key | Description |
|-----|--------------|
| `Path` | Full path to the file |
| `Size` | File size in KiB |
| `Type` | `"F"` for files |
| `Owner` | UID or username (if `resolve_users=True`) |
| `permOwner`, `permGroup`, `permOthers` | POSIX permissions in `rwx` form |
| `Inode` | File inode number |
| `CRC32` | Optional, only if `crc32=True` |
| `ElapsedSeconds` | Only appended at the end if `measure_time=True` |

Example:
```python
res = fsdir.go(".", summary=False, crc32=True, resolve_users=True, measure_time=True)
print(res[-1])  # {"ElapsedSeconds": 0.317}
```

---

### 2. When `summary=True`
Returns a single-element list summarizing totals:
```python
[
  {"Dirs": 12, "Files": 542, "Size": 155120, "ElapsedSeconds": 0.45}
]
```

---

### 3. When `output_file` is provided
Detailed results are streamed directly to disk (compact JSON array):

```python
meta = fsdir.go(
    "/data/archive",
    summary=False,
    crc32=False,
    resolve_users=True,
    measure_time=True,
    output_file="scan.json"
)
print(meta)
# [{'OutputFile': 'scan.json', 'Dirs': ..., 'Files': ..., 'Size': ..., 'ElapsedSeconds': ...}]
```

The file will contain:
```json
[
  {"Path": "/data/archive/file1", "Size": 16, "Owner": "alice", "Type": "F"},
  {"Path": "/data/archive/file2", "Size": 2048, "Owner": "bob", "Type": "F"},
  {"ElapsedSeconds": 1.472}
]
```

This mode avoids memory growth when scanning millions of files.

---
### 4. Benchmarks:
Benchmark using du as baseline on a data set with 64465 directories, 496167 Files, and a total size of 261GB.
 
```bash
$ /usr/bin/time -f %e du -smc /dataset/ > /dev/null
326.12

#Benchmark code: fsdir.go("/dataset/", summary=True, crc32=False, max_threads=i, resolve_users=False, measure_time=True, output_file=None)

Running with 2 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 171.327735196}

Running with 4 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 97.029060462}

Running with 6 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 83.050697647}

Running with 8 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 79.379940187}

Running with 10 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 78.613208631}

Running with 12 threads:
{'Dirs': 64465, 'Files': 496157, 'Size': 261555184, 'ElapsedSeconds': 78.635999863}

```

---

## ⚠️ Notes & Limits

- Default thread cap: up to 8 (based on available CPUs) when `max_threads=0`.
- Memory usage in non-streaming mode scales linearly with file count.
- CRC32 computation and username lookups add overhead.
- Works with both **absolute and relative** paths.

---

## 🧰 Error Handling

### `fsdir.errors()`
Returns a list of `[path, reason]` pairs for files or directories that couldn’t be accessed.

Example:
```python
errors = fsdir.errors()
if errors:
    for path, reason in errors:
        print(f"Error: {path}: {reason}")
```

---

## 🧮 Example Workflows

### Full detailed traversal (in memory)
```python
res = fsdir.go("/etc", summary=False, resolve_users=True, measure_time=True)
print(f"Scanned {len(res)-1} files in {res[-1]['ElapsedSeconds']:.3f}s")
```

### Summary-only
```python
summary = fsdir.go("/etc", summary=True, measure_time=True)
print(summary[0])
```

### Streaming to disk
```python
meta = fsdir.go(
    "/var/log",
    summary=False,
    output_file="logs.json",
    measure_time=True,
    resolve_users=True
)
print(f"Output written to {meta[0]['OutputFile']}")
```

### With CRC32 and fixed threads
```python
fsdir.go(
    "/data",
    summary=False,
    crc32=True,
    max_threads=32,  # user-defined, no hard limit
    output_file="crc_scan.json",
    measure_time=True
)
```

---

## 🧪 Testing

Run the comprehensive flag test suite:

```bash
python3 test_fsdir_all_flags_json.py
```

This script:
- Generates a temporary directory tree.
- Runs all valid flag combinations (≈48 cases).
- Verifies JSON correctness and timing fields.
- Cleans up automatically.

Expected output:
```
✓ Completed in 0.003s, returned 8 entries
✓ 9 JSON entries written to /tmp/fsdir_test_abcd/output.json
...
✅ All flag combinations tested successfully
```

---

## 🧱 Example Integration (CLI)

You can easily wrap `fsdir` in a simple CLI script:

```python
#!/usr/bin/env python3
import argparse, fsdir, json

p = argparse.ArgumentParser(description="Fast multithreaded filesystem scanner")
p.add_argument("path", help="Path to scan")
p.add_argument("--summary", action="store_true")
p.add_argument("--crc32", action="store_true")
p.add_argument("--resolve-users", action="store_true")
p.add_argument("--max-threads", type=int, default=0)
p.add_argument("--measure-time", action="store_true")
p.add_argument("--output", help="Write detailed JSON results to this file")
args = p.parse_args()

res = fsdir.go(
    args.path,
    summary=args.summary,
    crc32=args.crc32,
    max_threads=args.max_threads,
    resolve_users=args.resolve_users,
    measure_time=args.measure_time,
    output_file=args.output,
)

print(json.dumps(res, indent=2))
```

---

## 🧠 Internals

- **Work Queue:** Thread-safe cooperative queue with `queued`, `active`, and `stop` counters ensures no worker deadlocks.
- **Threads:** Spawned with `pthread_create`; now unlimited count based on user setting.
- **No GIL contention:** Worker threads never interact with Python APIs.
- **Username cache:** Thread-safe hash table (128 buckets) for UID lookups.
- **Streaming JSON:** Thread-safe file writes using minimal locking.

---

## 🧩 Version
`fsdir 1.0.0`

---

## 📜 License
MIT License © 2025 Rui Gomes
