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

EXPECTED_PKTS = {
    0: bytes.fromhex("14001bb842318de6a6d1ea9c6dedef680ec6a1528c6db35d5ce7"),
    1: bytes.fromhex("14019c57f35f952aaf18dcc90d0e5de82c514b2ccb9aafb82c84"),
    255: bytes.fromhex("14ff0c31f0c65041c3374562ad1c9578ce87b8dd7bda8d5a56ba"),
    256: bytes.fromhex("240001ff81f979d58a2a1f2d9c64a6ababb9903685c1cb7345e2e1"),
    65535: bytes.fromhex("24ffff1c721c15c67e56e43b5c5008629327134a96727a0ddbc97f"),
    65536: bytes.fromhex("340000012b05cafa4781e01c08389825228bcabff67a17985993d7b1"),
    16777215: bytes.fromhex("34ffffff356fb528be78754d09bb19f12a22278afe46cac0823fbd6e"),
    16777216: bytes.fromhex("4400000001b47142c0681c09658326d1075e0d85ca2a18e9840e30c52c"),
    1099511627775: bytes.fromhex("54ffffffffff00494fcc9445b57ed46794842daa11cbd7b52f932dd609ab"),
    18446744073709551615: bytes.fromhex("84ffffffffffffffff538355438205b22c890388b4e03971e4c6a7953a60668dca"),
}

EXPECTED_PKT_KAT = bytes.fromhex(
    "44776655448e8104bdf6ca06d9a3f211879b59e10232e21d853a4249fd"
)

EXPECTED_PRIVTOKEN_ENC = bytes.fromhex(
    "9ba9ab3641a11f1002391e02d109d6d5dbc790eb0d910143d24e313fa7a82d80"
    "875f0ab25d06d8da139ba54d566200cdb2b199d426b6d59e8b6847dcca9f743d"
    "f74317f22315e667ccc3ffbd5776325ba0de4616320453b9bd88bd0dd7800b75"
    "7cf276fbb63fd3e203cd9ef23eca9f21c7fb549c7a4f092adaeabea6660c823d"
    "a4c822c396ac3178258478de37341b3bb2d39517be9da524d5e75a1e0800d2a7"
    "1d39be413e52f98f88ac9652a31da011a30d0df3391aa949ae1a7b9fd2bf18de"
    "92347840377ca92c1937fd631e38dfdaa1dc9b7d82f2b4de1a4bda043925104a"
    "be462e49333263134bc05ee3b44957fcecf7caf9193d507d382e29cc0718fd94"
    "d74818153ea504f9df47ea4eba7e88bed885723dcb627bc44210484d35ddc128"
    "15abfab0676995af0a9cecb06ab687e57d58bba7e574fc343e2fa5a1359963ff"
    "a1c13a233dd56fd33fc04c3f016bc452f5d0cd46bf00fc4cbded20f2b3f8ccfa"
    "759563c5b754383d42b5d6c5e84a8b2716eb91482679e345b8c764fbda4b2f98"
    "0b3e83f4a795fd24eb2a5e0c64b3f221f7a9c83225b503cf11f0da280c91b274"
    "17c698a0ec462009506a97b850dc5d185045dfffbc6e3ea4fd17b76243d2c6a5"
    "63e9503befe4c51f22f273856a849528461004a186fe6798aaaf1e9be81d092e"
    "cee268f17bdbacb4dc5cad7f9cd18c511c120f96b9445145077dce0fe1f26cd9"
    "4f6c58aee07335a2f47b60b9ca9cca2516580c2c8db810566c95487de498562b"
    "f600c0cf2753fcf64435bfc52d87dd6eef1113819e861faa1bbad3a3a3724902"
    "20d6228c04baa33e1d252ded5224045c408772dc2d1827c68462c9517c930610"
    "093fe38dc9db51e095724bfbaabf4f2b73073b3bdef8d6359ab8b6134c2fcfc7"
    "94183dcf3ef3db7e1207544fcafc1f612a844e52c6aaab55925f6e3b1fca62dd"
    "bb7573f3beba8c65cb3ed815eed2c273df4c707083e107d51ae034b4090932a2"
    "12f06f7ca16b32fbfbde901a750c63a7eb470846437a438b711e55ccaa15a1b3"
    "8c3c0232d65f49b8145ded5ec02bccb7ece7e6e86d2440bda681989cbe2e5881"
    "4a0b5ec2dc963c3056e06151742e2b3de5baa95510b7a2e9a121c971ab96e89d"
    "f0ac3f1dc618f5629fc6454cf926ac0a8f6df2a1a0547880403236288e325880"
    "718be9cf5390ef1135c0d70179386ec6ba94a2437b5213606fc0d95f132d54d3"
    "3262d14d197b3ff020d51457098159e9a9514f0f813f3055bda70d9024c8ebc6"
    "bf1f4bde685f841997aab7327f5f771115bf4c91b9a4dd7fb2ac3f677cf44345"
    "0c8413b26dd2ce1d4cd5f3416cc0e519e487c9ec3b12dbf797614ba914e0f107"
    "4a5c97958539995472c4cad855581f472a1fb946cc10d13ea4d9af94de5d66bb"
    "e3924b12dc2530a45c12487ffbd24dfebeae3fb93a73242dc5a69ad09e39a941"
)

EXPECTED_CHALLENGE_ENC = bytes.fromhex(
    "90dd664e430aaf1f6e6965da4117deeb384706e55e84b2b50c33b98345bbdc8c"
    "84bb85259df02c821e20a14deb556cdbc0fd3c5269ffadfca3ef2a329f70e3cb"
    "652ccbf3167fd288487c4e8fbba22e6494c215a3c1df363e66740e6239e7fd8e"
    "99a42018b37d618df69a6d7fafcb1151eef713901fdaa42509045037c3f0928b"
    "55471971ddb865f05aed73ac6077fa126e33b570ce3b0b10a30b36c5f28355d8"
    "a2039702051bcf91d6db76f3b329521ac752c7a8916e3d6981c1a622a785eafc"
    "5b08838ec54e31c1a45b494f2086075845bfde03ed5fe2fafca1bfe8006627b7"
    "573aecdfc97d1b0601c4b6022f8fa62470414a92630108a668b2bf57478d6a3a"
    "e9c6bcb08708169b2e02ba681fe62f2358a7d83ff26703d2f5d10f6e662c668d"
    "541c0ccfeb9499b50fa50696"
)


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

    token, packets, challenge = None, [], None
    pkt_kat, privtoken_enc, challenge_enc = None, None, None
    for line in build_and_run(a.cc).splitlines():
        if line.startswith("TOKEN "):
            _, n, h = line.split(); token = bytes.fromhex(h); assert int(n) == len(token)
        elif line.startswith("CHALLENGE "):
            _, n, h = line.split(); challenge = bytes.fromhex(h); assert int(n) == len(challenge)
        elif line.startswith("PKT_KAT "):
            _, n, h = line.split(); pkt_kat = bytes.fromhex(h); assert int(n) == len(pkt_kat)
        elif line.startswith("PRIVTOKEN_ENC "):
            _, n, h = line.split(); privtoken_enc = bytes.fromhex(h); assert int(n) == len(privtoken_enc)
        elif line.startswith("CHALLENGE_ENC "):
            _, n, h = line.split(); challenge_enc = bytes.fromhex(h); assert int(n) == len(challenge_enc)
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
        if seq in EXPECTED_PKTS:
            c.eq(f"seq {seq}: encrypted wire packet KAT", p, EXPECTED_PKTS[seq])

    # ---- Challenge token. STANDARD.md, "Prior to encryption, challenge tokens have the following structure"
    if challenge is not None:
        c.eq("challenge token size (zero pad to 300)", len(challenge), 300)
        c.eq("challenge client id", struct.unpack_from("<Q", challenge, 0)[0], 0x0102030405060708)
        c.eq("challenge user data (256 bytes)",
             challenge[8:8 + 256], bytes((i ^ 0x5A) for i in range(256)))
        c.eq("challenge zero pad after client id + user data",
             set(challenge[8 + 256:300]) or {0}, {0})
        c.eq("challenge plaintext leaves room for the 16-byte HMAC",
             300 - (8 + 256) >= 16, True)

    # ---- Encrypted wire KAT vectors (packet, private connect token, challenge token)
    c.eq("encrypted packet KAT vector", pkt_kat, EXPECTED_PKT_KAT)
    c.eq("encrypted private connect token KAT vector", privtoken_enc, EXPECTED_PRIVTOKEN_ENC)
    c.eq("encrypted challenge token KAT vector", challenge_enc, EXPECTED_CHALLENGE_ENC)

    print(f"{c.n} checks against STANDARD.md, {len(c.fails)} failures")
    for f in c.fails: print("  FAIL " + f)
    if c.fails:
        print("\nSTANDARD.md and the implementation disagree. One of them is wrong.")
        return 1
    print("\nSTANDARD.md matches the implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
