#!/usr/bin/env python3
"""Check netcode/STANDARD.md's client state machine against the implementation.

Drives a real client and server through a full connection lifecycle over UDP,
records every client state transition, and checks the observed behaviour
against the machine STANDARD.md specifies. Nothing here consults netcode.c;
the states and legal transitions below are transcribed from the document.

usage: python3 tools/conformance/verify_state_machine.py [--cc CC]
exit:  0 = they agree, 1 = they do not, 2 = could not build/run
"""
import argparse, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# STANDARD.md, "Client State Machine". Negative states are errors; 0 is the
# initial state; 3 is the goal state.
TOKEN_EXPIRED, INVALID_TOKEN, CONN_TIMEOUT = -6, -5, -4
RESPONSE_TIMEOUT, REQUEST_TIMEOUT, DENIED = -3, -2, -1
DISCONNECTED, SENDING_REQUEST, SENDING_RESPONSE, CONNECTED = 0, 1, 2, 3

NAME = {TOKEN_EXPIRED: "connect token expired", INVALID_TOKEN: "invalid connect token",
        CONN_TIMEOUT: "connection timed out", RESPONSE_TIMEOUT: "connection response timed out",
        REQUEST_TIMEOUT: "connection request timed out", DENIED: "connection denied",
        DISCONNECTED: "disconnected", SENDING_REQUEST: "sending connection request",
        SENDING_RESPONSE: "sending challenge response", CONNECTED: "connected"}

# Every transition STANDARD.md permits, with the sentence that licenses it.
LEGAL = {
    (DISCONNECTED, SENDING_REQUEST),      # "it transitions to sending connection request"
    (DISCONNECTED, INVALID_TOKEN),        # token fails validation before the attempt
    (SENDING_REQUEST, SENDING_RESPONSE),  # challenge packet received
    (SENDING_REQUEST, DENIED),            # connection denied packet
    (SENDING_REQUEST, REQUEST_TIMEOUT),   # neither challenge nor denied within timeout
    (SENDING_RESPONSE, CONNECTED),        # keep-alive received
    (SENDING_RESPONSE, DENIED),           # denied while sending challenge response
    (SENDING_RESPONSE, RESPONSE_TIMEOUT), # neither keep-alive nor denied within timeout
    (SENDING_RESPONSE, SENDING_REQUEST),  # retry against the next server address
    (CONNECTED, DISCONNECTED),            # disconnect packet, or the client disconnecting
    (CONNECTED, CONN_TIMEOUT),            # no payload or keep-alive within timeout
}
# "If the entire client connection process ... takes long enough that the connect
# token expires" — reachable from any non-terminal state in the attempt.
for s in (DISCONNECTED, SENDING_REQUEST, SENDING_RESPONSE):
    LEGAL.add((s, TOKEN_EXPIRED))
# A client may abandon an attempt at any point; the spec's disconnect path ends here.
for s in (SENDING_REQUEST, SENDING_RESPONSE):
    LEGAL.add((s, DISCONNECTED))


def build_and_run(cc):
    src = os.path.join(ROOT, "tools", "conformance", "drive_state_machine.c")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "drive")
        cmd = [cc, "-I" + ROOT, "-I" + os.path.join(ROOT, "sodium"), "-o", exe, src,
               os.path.join(ROOT, "netcode.c"), os.path.join(ROOT, "sodium", "sodium.c")]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("build failed:\n" + r.stderr[:1500], file=sys.stderr); sys.exit(2)
        r = subprocess.run([exe], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            print("driver failed:\n" + (r.stdout + r.stderr)[:1500], file=sys.stderr); sys.exit(2)
        return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    a = ap.parse_args()

    transitions, result = [], None
    for line in build_and_run(a.cc).splitlines():
        f = line.split()
        if f[0] == "STATE":   transitions.append((int(f[1]), int(f[2]), f[3]))
        elif f[0] == "RESULT": result = f[1:]

    checks, fails = 0, []
    def eq(name, got, exp):
        nonlocal checks; checks += 1
        if got != exp: fails.append(f"{name}: got {got!r}, STANDARD.md says {exp!r}")

    eq("driver completed the lifecycle", result and result[0], "ok")
    eq("initial state is disconnected (0)", transitions[0][0], DISCONNECTED)

    for frm, to, phase in transitions:
        if frm == to: continue
        checks += 1
        if (frm, to) not in LEGAL:
            fails.append(f"ILLEGAL transition '{NAME.get(frm,frm)}' -> '{NAME.get(to,to)}' "
                         f"during '{phase}' is not permitted by STANDARD.md")

    moves = [(f, t) for f, t, _ in transitions if f != t]

    eq("happy path is disconnected -> sending request -> sending response -> connected -> disconnected",
       moves, [(DISCONNECTED, SENDING_REQUEST), (SENDING_REQUEST, SENDING_RESPONSE),
               (SENDING_RESPONSE, CONNECTED), (CONNECTED, DISCONNECTED)])

    # "When the client receives a connection keep-alive packet ... transitions to connected"
    # is the ONLY route in. Nothing may reach the goal state by another path.
    for frm, to in moves:
        if to == CONNECTED:
            checks += 1
            if frm != SENDING_RESPONSE:
                fails.append(f"entered 'connected' from '{NAME.get(frm,frm)}'; STANDARD.md "
                             "admits only 'sending challenge response'")

    eq("no state change while connected and idle",
       [p for f, t, p in transitions if f != t and p == "steady"], [])

    # A clean disconnect is state 0, never an error state. The distinction is the
    # difference between "the server said goodbye" and "something broke".
    eq("clean disconnect ends in disconnected, not an error state",
       moves[-1][1], DISCONNECTED)
    checks += 1
    if any(t < 0 for _, t in moves):
        fails.append("an error state was reached during a clean lifecycle")

    # ---- error path: the transitions the happy path never exercises.
    # STANDARD.md lists six error states; the happy-path driver reaches none of
    # them, so the legal transitions into them were transcribed but untested.
    # This provokes the connection-request timeout deterministically (a token
    # pointed at an address where nothing listens) and checks the machine takes
    # the licensed failure path rather than some other route.
    err_src = os.path.join(ROOT, "tools", "conformance", "drive_error_paths.c")
    # No silent skip: this driver is committed beside the checker, so its
    # absence is a fault, not a reason to quietly check less. (The floors-test
    # lesson: `if exists` around an assertion lets a rename disable a check
    # while the suite stays green.)
    checks += 1
    if not os.path.exists(err_src):
        fails.append("drive_error_paths.c is missing — the error-path phase cannot run")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            exe = os.path.join(tmp, "err")
            r = subprocess.run([a.cc, "-I" + ROOT, "-I" + os.path.join(ROOT, "sodium"),
                                "-o", exe, err_src, os.path.join(ROOT, "netcode.c"),
                                os.path.join(ROOT, "sodium", "sodium.c")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                fails.append("error-path driver failed to build")
            else:
                out = subprocess.run([exe], capture_output=True, text=True, timeout=120).stdout
                emoves, eresult = [], None
                for line in out.splitlines():
                    f = line.split()
                    if f[0] == "STATE" and int(f[1]) != int(f[2]):
                        emoves.append((int(f[1]), int(f[2])))
                    elif f[0] == "RESULT":
                        eresult = f[1:]
                eq("error path reached an error state", eresult and eresult[0], "ok")
                for frm, to in emoves:
                    checks += 1
                    if (frm, to) not in LEGAL:
                        fails.append(f"error-path transition '{NAME.get(frm,frm)}' -> "
                                     f"'{NAME.get(to,to)}' is not permitted by STANDARD.md")
                # the request-timeout must be reached FROM sending-request, never
                # from disconnected or by skipping the request stage
                to_timeout = [f for f, t in emoves if t == REQUEST_TIMEOUT]
                if REQUEST_TIMEOUT in [t for _, t in emoves]:
                    eq("request-timeout entered from sending-request",
                       to_timeout, [SENDING_REQUEST])
                else:
                    fails.append("expected CONNECTION_REQUEST_TIMED_OUT, reached "
                                 + str([NAME.get(t,t) for _,t in emoves]))

    # ---- server-side connection process. STANDARD.md's "Server-Side Connection
    # Process": the server manages slots [0, max_clients); a client connects into
    # a slot, the server sees it, and a disconnect frees the slot. The client
    # state machine above never checks any of this.
    srv_src = os.path.join(ROOT, "tools", "conformance", "drive_server.c")
    checks += 1
    if not os.path.exists(srv_src):
        fails.append("drive_server.c is missing — the server-side phase cannot run")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            exe = os.path.join(tmp, "srv")
            r = subprocess.run([a.cc, "-I" + ROOT, "-I" + os.path.join(ROOT, "sodium"),
                                "-o", exe, srv_src, os.path.join(ROOT, "netcode.c"),
                                os.path.join(ROOT, "sodium", "sodium.c")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                fails.append("server driver failed to build")
            else:
                out = subprocess.run([exe], capture_output=True, text=True, timeout=120).stdout
                events, result, maxc = [], None, None
                for line in out.splitlines():
                    f = line.split()
                    if f[0] == "SLOT":
                        events.append(f[1:])
                        if f[1] == "baseline":
                            maxc = int(f[4].split("=")[1])
                    elif f[0] == "RESULT":
                        result = f[1:]
                EXPECTED_ID = 0x1234567890ABCDEF
                eq("server driver completed", result and result[0], "ok")
                base = [e for e in events if e[0] == "baseline"]
                conn = [e for e in events if e[0] == "connected"]
                freed = [e for e in events if e[0] == "freed"]
                idle = [e for e in events if e[0] == "changed_while_idle"]
                eq("baseline: zero clients connected", base and base[0][2], "0")
                eq("exactly one client connected", len(conn), 1)
                if conn:
                    slot, num = int(conn[0][1]), int(conn[0][2])
                    eq("connect slot in [0, max_clients)", 0 <= slot < (maxc or 0), True)
                    eq("num_connected is 1 at connect", num, 1)
                    got_id = int(conn[0][3].split("=")[1])
                    eq("server reports the client's own id", got_id, EXPECTED_ID)
                eq("no spurious slot change while idle", idle, [])
                eq("exactly one slot freed on disconnect", len(freed), 1)
                if freed:
                    eq("num_connected back to 0 after free", int(freed[0][2]), 0)
                    if conn:
                        eq("the freed slot is the one that connected", freed[0][1], conn[0][1])

    # ---- invalid connect token. STANDARD.md: the client validates the token
    # BEFORE the connection attempt, and on a bad num_server_addresses transitions
    # straight to INVALID_CONNECT_TOKEN without ever sending a request. The error
    # path above covers a timeout mid-handshake; this covers pre-attempt rejection.
    inv_src = os.path.join(ROOT, "tools", "conformance", "drive_invalid_token.c")
    checks += 1
    if not os.path.exists(inv_src):
        fails.append("drive_invalid_token.c is missing — the invalid-token phase cannot run")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            exe = os.path.join(tmp, "inv")
            r = subprocess.run([a.cc, "-I" + ROOT, "-I" + os.path.join(ROOT, "sodium"),
                                "-o", exe, inv_src, os.path.join(ROOT, "netcode.c"),
                                os.path.join(ROOT, "sodium", "sodium.c")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                fails.append("invalid-token driver failed to build")
            else:
                out = subprocess.run([exe], capture_output=True, text=True, timeout=120).stdout
                imoves, iresult = [], None
                for line in out.splitlines():
                    f = line.split()
                    if f[0] == "STATE" and int(f[1]) != int(f[2]):
                        imoves.append((int(f[1]), int(f[2])))
                    elif f[0] == "RESULT":
                        iresult = f[1:]
                eq("invalid-token driver reached the rejection", iresult and iresult[0], "ok")
                for frm, to in imoves:
                    checks += 1
                    if (frm, to) not in LEGAL:
                        fails.append(f"invalid-token transition {NAME.get(frm,frm)} -> "
                                     f"{NAME.get(to,to)} is not permitted by STANDARD.md")
                # the whole point: reached INVALID_TOKEN, and DIRECTLY from disconnected
                # (validation before the attempt), never via sending-request
                eq("reached invalid-connect-token", INVALID_TOKEN in [t for _, t in imoves], True)
                eq("invalid-token entered from disconnected (pre-attempt validation)",
                   [f for f, t in imoves if t == INVALID_TOKEN], [DISCONNECTED])

    print(f"{checks} checks against STANDARD.md, {len(fails)} failures")
    print("  observed: " + " -> ".join([NAME.get(moves[0][0], "?")] + [NAME.get(t, "?") for _, t in moves]))
    for f in fails: print("  FAIL " + f)
    if fails:
        print("\nSTANDARD.md and the implementation disagree. One of them is wrong.")
        return 1
    print("\nSTANDARD.md's client state machine matches the implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
