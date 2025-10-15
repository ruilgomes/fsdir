import os
import fsdir
import tempfile
import shutil
import random
import string
import time
import json
import traceback

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def make_tree(root, depth=2, fanout=2, files_per_dir=2):
    """Create a small but nested directory tree with files and empty dirs."""
    os.makedirs(root, exist_ok=True)
    for level in range(depth):
        for d in range(fanout):
            subdir = os.path.join(root, f"dir_{level}_{d}")
            os.makedirs(subdir, exist_ok=True)
            for f in range(files_per_dir):
                path = os.path.join(subdir, f"file_{f}.txt")
                with open(path, "w") as fh:
                    fh.write("".join(random.choices(string.ascii_letters, k=512)))
    os.makedirs(os.path.join(root, "empty_dir"), exist_ok=True)


def read_json_file(path, expect_elapsed=False):
    """Load JSON array and validate structure."""
    with open(path, "r") as f:
        data = json.load(f)
    assert isinstance(data, list), "Output file must contain a JSON array"
    if expect_elapsed:
        assert data and "ElapsedSeconds" in data[-1], (
            "Expected ElapsedSeconds in final element, got: %r" % data[-1]
        )
    return data


def verify_in_memory_output(result, summary, measure_time):
    """Check correctness of in-memory results."""
    assert isinstance(result, list), "Result must be a list"
    assert len(result) > 0, "Empty result list"

    if summary:
        row = result[0]
        assert isinstance(row, dict), "Summary row must be dict"
        assert "Dirs" in row and "Files" in row and "Size" in row
        if measure_time:
            assert "ElapsedSeconds" in row
    else:
        assert all(isinstance(x, dict) for x in result), "Detailed rows must be dicts"
        if measure_time:
            assert "ElapsedSeconds" in result[-1], "Missing ElapsedSeconds entry in detailed output"


def run_case(tmpdir, summary, crc32, resolve_users, measure_time, max_threads, output_file):
    """Execute one fsdir.go() run with given flags and validate output."""
    print(
        f"\n=== summary={summary} crc32={crc32} resolve_users={resolve_users} "
        f"measure_time={measure_time} max_threads={max_threads} output_file={output_file} ==="
    )
    try:
        output_path = os.path.join(tmpdir, output_file) if output_file else None
        t0 = time.time()
        res = fsdir.go(
            tmpdir,
            summary=summary,
            crc32=crc32,
            max_threads=max_threads,
            resolve_users=resolve_users,
            measure_time=measure_time,
            output_file=output_path,
        )
        dt = time.time() - t0
        print(f"✓ Completed in {dt:.3f}s, returned {len(res)} entries")

        # Verify in-memory part
        verify_in_memory_output(res, summary, measure_time)

        # Verify JSON file output if applicable
        if output_file:
            assert os.path.exists(output_path), f"Expected {output_path} to exist"
            data = read_json_file(output_path, expect_elapsed=measure_time)
            print(f"✓ {len(data)} JSON entries written to {output_path}")

            # Cross-check consistency between Python return and JSON
            last = res[-1]
            assert isinstance(last, dict)
            assert "Dirs" in last and "Files" in last and "Size" in last
            if measure_time:
                assert "ElapsedSeconds" in last
                assert abs(data[-1]["ElapsedSeconds"] - last["ElapsedSeconds"]) < 1.0

    except Exception as e:
        print("❌ Test failed with exception:")
        traceback.print_exc()
        raise


# ---------------------------------------------------------------------
# Main test driver
# ---------------------------------------------------------------------
if __name__ == "__main__":
    tmpdir = tempfile.mkdtemp(prefix="fsdir_test_")
    print(f"Creating test tree at: {tmpdir}")
    make_tree(tmpdir, depth=2, fanout=2, files_per_dir=2)

    bools = [False, True]
    total_cases = 0

    for summary in bools:
        for crc32 in bools:
            for resolve_users in bools:
                for measure_time in bools:
                    for max_threads in [0, 2]:
                        for output_flag in [None, "output.json"]:
                            # skip invalid combo: output_file only for summary=False
                            if summary and output_flag:
                                continue
                            total_cases += 1
                            run_case(
                                tmpdir,
                                summary,
                                crc32,
                                resolve_users,
                                measure_time,
                                max_threads,
                                output_flag,
                            )

    # -----------------------------------------------------------------
    # Single file test
    # -----------------------------------------------------------------
    single_file = os.path.join(tmpdir, "one.txt")
    with open(single_file, "w") as fh:
        fh.write("hello single file\n")

    print("\n=== Single file path test ===")
    res = fsdir.go(single_file, summary=False, crc32=True, measure_time=True)
    verify_in_memory_output(res, summary=False, measure_time=True)
    print("✓ Single file test passed")

    # -----------------------------------------------------------------
    # Empty directory test
    # -----------------------------------------------------------------
    empty_dir = os.path.join(tmpdir, "empty_dir")
    print("\n=== Empty directory test ===")
    res = fsdir.go(empty_dir, summary=True, measure_time=True)
    verify_in_memory_output(res, summary=True, measure_time=True)
    print("✓ Empty directory test passed")

    print(f"\n✅ All {total_cases} flag combinations tested successfully")
    shutil.rmtree(tmpdir)

