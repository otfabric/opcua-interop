"""Requests the client commands build (client.py)."""

import unittest

from asyncua import ua
from asyncua.ua.ua_binary import struct_to_binary

from opcua_interop_asyncua import client


class NullViewTest(unittest.TestCase):
    def test_null_view_encodes_as_zeros(self):
        # ViewId i=0 (TwoByte, 2 bytes), Timestamp null (8), ViewVersion 0 (4).
        self.assertEqual(struct_to_binary(client.null_view()), bytes(14))

    def test_stack_default_has_a_timestamp(self):
        # Why null_view exists: asyncua 2.1.0 fills Timestamp with the current
        # time. When this fails, the stack sends a null view by itself.
        self.assertNotEqual(struct_to_binary(ua.ViewDescription())[2:10], bytes(8))


if __name__ == "__main__":
    unittest.main()
