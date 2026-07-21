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
