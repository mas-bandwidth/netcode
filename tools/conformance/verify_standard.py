#!/usr/bin/env python3
"""Check netcode/STANDARD.md against the implementation.

Parses artifacts produced by the real library using ONLY what STANDARD.md
states. Nothing here consults netcode.c. If the document and the code disagree,
this fails and one of them is wrong.

usage: python3 tools/conformance/verify_standard.py [--cc CC]
exit:  0 = they agree, 1 = they do not, 2 = could not build/run
"""
import argparse, os, struct, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_and_run(cc):
    src = os.path.join(ROOT, "tools", "conformance", "gen_vectors.c")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "gen")
        cmd = [cc, "-I" + ROOT, "-I" + os.path.join(ROOT, "sodium"), "-o", exe, src,
               os.path.join(ROOT, "netcode.c"), os.path.join(ROOT, "sodium", "sodium.c")]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("build failed:\n" + r.stderr[:2000], file=sys.stderr)
            sys.exit(2)
        r = subprocess.run([exe], capture_output=True, text=True)
        if r.returncode != 0:
            print("generator failed:\n" + r.stderr[:2000], file=sys.stderr)
            sys.exit(2)
        return r.stdout


class Checker:
    def __init__(self): self.n = 0; self.fails = []
    def eq(self, name, got, exp):
        self.n += 1
        if got != exp: self.fails.append(f"{name}: got {got!r}, STANDARD.md says {exp!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    a = ap.parse_args()

    token, packets = None, []
    for line in build_and_run(a.cc).splitlines():
        if line.startswith("TOKEN "):
            _, n, h = line.split(); token = bytes.fromhex(h); assert int(n) == len(token)
        elif line.startswith("PKT "):
            p = line.split(); packets.append((int(p[1]), bytes.fromhex(p[3])))
    if token is None or not packets:
        print("generator produced no vectors", file=sys.stderr); sys.exit(2)

    c = Checker()

    # ---- Connect token. STANDARD.md, "Together the public and private data form a connect token"
    c.eq("connect token size", len(token), 2048)
    o = 0
    c.eq("version info", token[0:13], b"NETCODE 1.02\x00"); o = 13
    c.eq("protocol id", struct.unpack_from("<Q", token, o)[0], 0x1234567890ABCDEF); o += 8
    create = struct.unpack_from("<Q", token, o)[0]; o += 8
    expire = struct.unpack_from("<Q", token, o)[0]; o += 8
    c.eq("expire - create == expire_seconds", expire - create, 45)
    o += 24        # connect token nonce
    o += 1024      # encrypted private connect token data
    c.eq("timeout seconds", struct.unpack_from("<i", token, o)[0], 17); o += 4
    n_addr = struct.unpack_from("<I", token, o)[0]; o += 4
    c.eq("num server addresses", n_addr, 2)
    addrs = []
    for _ in range(n_addr):
        t = token[o]; o += 1
        if t == 1:
            q = token[o:o + 4]; o += 4
            port = struct.unpack_from("<H", token, o)[0]; o += 2
            addrs.append(".".join(str(x) for x in q) + f":{port}")
        elif t == 2:
            parts = struct.unpack_from("<8H", token, o); o += 16
            port = struct.unpack_from("<H", token, o)[0]; o += 2
            addrs.append("[" + ":".join(f"{x:x}" for x in parts) + f"]:{port}")
        else:
            c.fails.append(f"address type {t} is not 1 (IPv4) or 2 (IPv6)")
    c.eq("address 0 (IPv4)", addrs[0], "127.0.0.1:40000")
    c.eq("address 1 is IPv6 on port 40001",
         addrs[1].startswith("[") and addrs[1].endswith(":40001"), True)
    o += 32 + 32   # client->server key, server->client key
    c.eq("zero pad to 2048", set(token[o:2048]) or {0}, {0})

    # ---- Packets. STANDARD.md, "Prior to encryption, packet types >= 1"
    for seq, p in packets:
        prefix = p[0]
        c.eq(f"seq {seq}: packet type (low 4 bits) is keep-alive", prefix & 0x0F, 4)
        nseq = (prefix >> 4) & 0x0F
        c.eq(f"seq {seq}: sequence byte count in [1,8]", 1 <= nseq <= 8, True)
        c.eq(f"seq {seq}: high zero bytes omitted", nseq, max(1, (seq.bit_length() + 7) // 8))
        v = 0
        for i in range(nseq):
            v |= p[1 + i] << (8 * i)
        c.eq(f"seq {seq}: sequence round-trips", v, seq)

    print(f"{c.n} checks against STANDARD.md, {len(c.fails)} failures")
    for f in c.fails: print("  FAIL " + f)
    if c.fails:
        print("\nSTANDARD.md and the implementation disagree. One of them is wrong.")
        return 1
    print("\nSTANDARD.md matches the implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
