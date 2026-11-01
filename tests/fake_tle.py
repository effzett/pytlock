"""Ersatz für tle in Unit-Tests: reversibel, KEINE Kryptografie.
Entschlüsseln gelingt nur, wenn FAKE_TLE_LATEST >= Runde."""
import os
import sys


def main() -> int:
    args = sys.argv[1:]
    decrypt = "-d" in args
    rnd = int(args[args.index("-r") + 1]) if "-r" in args else None
    data = sys.stdin.buffer.read()
    out = sys.stdout.buffer
    if not decrypt:
        out.write(b"FAKETLE %d\n" % rnd + bytes(b ^ 0x5A for b in data))
        return 0
    head, _, body = data.partition(b"\n")
    if not head.startswith(b"FAKETLE "):
        sys.stderr.write("age: no identity matched\n")
        return 1
    if int(os.environ.get("FAKE_TLE_LATEST", "0")) < int(head.split()[1]):
        sys.stderr.write("too early to decrypt\n")
        return 1
    out.write(bytes(b ^ 0x5A for b in body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
