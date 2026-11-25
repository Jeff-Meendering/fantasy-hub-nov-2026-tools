#!/usr/bin/env python3
"""Encode/decode Fantasy Hub (Nov 2026) outgoing WebSocket frames."""

import base64
import json
import sys

TOOL_VERSION = "2.3"
KEY = b"MySuperSecretKeyForData"


def to_mutf8(s: str, jni_spec: bool = False) -> bytes:
    """Encode a string the way GetStringUTFChars hands it to mdnaboec().

    NUL becomes C0 80 either way. Android's runtime (ART) encodes emoji and other
    supplementary characters as normal 4-byte UTF-8, which is the default here.
    jni_spec=True gives the JNI-spec form instead (two 3-byte surrogate halves).
    """
    if jni_spec:
        units = s.encode("utf-16-le", "surrogatepass")
        s = "".join(chr(int.from_bytes(units[i : i + 2], "little")) for i in range(0, len(units), 2))
    return s.encode("utf-8", "surrogatepass").replace(b"\x00", b"\xc0\x80")


def from_mutf8(b: bytes) -> str:
    # Accepts both forms: 4-byte UTF-8 (ART) and 3-byte surrogate halves (JNI spec).
    b = b.replace(b"\xc0\x80", b"\x00")
    return b.decode("utf-8", "surrogatepass").encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _xor(data: bytes) -> bytes:
    return bytes(b ^ (i & 0xFF) ^ KEY[i % len(KEY)] for i, b in enumerate(data))


def encrypt(pt: str, jni_spec: bool = False) -> str:
    return base64.b64encode(_xor(to_mutf8(pt, jni_spec))).decode()


def decrypt(b64: str) -> str:
    return from_mutf8(_xor(base64.b64decode(b64)))


def decrypt_frame(frame: str) -> str:
    s = frame.strip()
    if s.startswith("{"):
        obj = json.loads(s)
        if "p" not in obj:
            return s  # plaintext keepalive
        s = obj["p"]
    return decrypt(s)


if __name__ == "__main__":
    args = sys.argv[1:]
    jni_spec = "--jni-spec" in args
    args = [a for a in args if a != "--jni-spec"]
    if args[:1] == ["--encrypt"]:
        for line in args[1:] or sys.stdin.read().splitlines():
            print(json.dumps({"p": encrypt(line, jni_spec)}))
    else:
        for line in args or sys.stdin.read().splitlines():
            if line.strip():
                print(decrypt_frame(line))
