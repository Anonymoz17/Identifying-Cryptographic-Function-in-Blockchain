import sys
import time

sys.path.insert(0, "src")
from auditor.intake import enumerate_inputs_iter  # noqa: E402

if __name__ == "__main__":
    it = enumerate_inputs_iter(["."], compute_sha=False)
    start = time.time()
    count = 0
    try:
        for _ in it:
            count += 1
            if count % 10 == 0:
                print("seen", count)
            if count >= 100:
                break
    except Exception as e:
        print("error during enumerate:", e)
    print("done, time:", time.time() - start)
