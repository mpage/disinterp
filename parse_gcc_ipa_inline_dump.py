import argparse
import re


SUMMARY_PREFIX = "IPA function summary for _PyEval_EvalFrameDefault"

STATE_START = 0
STATE_SEEN_FIRST_SUMMARY = 1
STATE_IN_SECOND_SUMMARY = 2

INLINED_RE = r"^    ([^\s]+) inlined"


def parse_inlining_logs(path: str) -> None:
    state = STATE_START
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            if state == STATE_START:
                if line.startswith(SUMMARY_PREFIX):
                    state = STATE_SEEN_FIRST_SUMMARY
            elif state == STATE_SEEN_FIRST_SUMMARY:
                if line.startswith(SUMMARY_PREFIX):
                    state = STATE_IN_SECOND_SUMMARY
            elif state == STATE_IN_SECOND_SUMMARY:
                if line.startswith("  "):
                    matches = re.match(INLINED_RE, line)
                    if matches:
                        print(matches.group(1))
                else:
                    break



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse GCC's IPA inline dump file and print all calls inlined into the interpreter loop")
    parser.add_argument("path", help="Path to the dump file")
    args = parser.parse_args()
    parse_inlining_logs(args.path)
