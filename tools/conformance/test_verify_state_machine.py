#!/usr/bin/env python3
"""Unit test for verify_state_machine.py's transition table.

Feeds state traces to the checker's LEGAL set: traces STANDARD.md permits must
pass, and traces it forbids must be rejected. No build, no sockets, no time.

usage: python3 tools/conformance/test_verify_state_machine.py
"""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_state_machine as vsm


def rejected(trace):
    """The moves in a state trace that the checker would flag as illegal."""
    return [(f, t) for f, t in zip(trace, trace[1:]) if f != t and (f, t) not in vsm.LEGAL]


class TransitionTable(unittest.TestCase):

    def test_valid_traces_are_accepted(self):
        for trace in (
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.SENDING_RESPONSE, vsm.CONNECTED, vsm.DISCONNECTED],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.SENDING_RESPONSE, vsm.SENDING_REQUEST,
             vsm.SENDING_RESPONSE, vsm.CONNECTED, vsm.CONN_TIMEOUT],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.REQUEST_TIMEOUT],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.DENIED],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.SENDING_RESPONSE, vsm.RESPONSE_TIMEOUT],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.TOKEN_EXPIRED],
            [vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.SENDING_RESPONSE, vsm.TOKEN_EXPIRED],
            [vsm.DISCONNECTED, vsm.INVALID_TOKEN],
        ):
            self.assertEqual(rejected(trace), [], trace)

    def test_invalid_traces_are_rejected(self):
        for trace, bad in (
            ([vsm.DISCONNECTED, vsm.TOKEN_EXPIRED], (vsm.DISCONNECTED, vsm.TOKEN_EXPIRED)),
            ([vsm.DISCONNECTED, vsm.CONNECTED], (vsm.DISCONNECTED, vsm.CONNECTED)),
            ([vsm.DISCONNECTED, vsm.DENIED], (vsm.DISCONNECTED, vsm.DENIED)),
            ([vsm.DISCONNECTED, vsm.REQUEST_TIMEOUT], (vsm.DISCONNECTED, vsm.REQUEST_TIMEOUT)),
            ([vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.CONNECTED], (vsm.SENDING_REQUEST, vsm.CONNECTED)),
            ([vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.SENDING_RESPONSE, vsm.CONNECTED,
              vsm.TOKEN_EXPIRED], (vsm.CONNECTED, vsm.TOKEN_EXPIRED)),
            ([vsm.DISCONNECTED, vsm.SENDING_REQUEST, vsm.INVALID_TOKEN], (vsm.SENDING_REQUEST, vsm.INVALID_TOKEN)),
        ):
            self.assertIn(bad, rejected(trace), trace)


if __name__ == "__main__":
    unittest.main()
