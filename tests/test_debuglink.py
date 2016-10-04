import time
import unittest
import common
import binascii

from trezorlib import mapping
from trezorlib.client import PinException

class TestDebugLink(common.TrezorTest):

    def test_layout(self):
        layout = self.client.debug.read_layout()
        self.assertEqual(len(layout), 1024)

    def test_mnemonic(self):
        self.setup_mnemonic_nopin_nopassphrase()
        mnemonic = self.client.debug.read_mnemonic()
        self.assertEqual(mnemonic, self.mnemonic12)

    def test_node(self):
        self.setup_mnemonic_nopin_nopassphrase()
        node = self.client.debug.read_node()
        self.assertIsNone(node) # Node is empty when setup is done by mnemonic

    def test_pin(self):
        self.setup_mnemonic_pin_passphrase()

        # Manually trigger PinMatrixRequest
        resp = self.client.call_raw(mapping.get_class('Ping')(message='test', pin_protection=True))
        print('XXX', resp, mapping.get_class('PinMatrixRequest'))
        self.assertEqual(resp, mapping.get_class('PinMatrixRequest'))

        pin = self.client.debug.read_pin()
        self.assertEqual(pin[0], '1234')
        self.assertNotEqual(pin[1], '')

        pin_encoded = self.client.debug.read_pin_encoded()
        resp = self.client.call_raw(mapping.get_class('PinMatrixAck')(pin=pin_encoded))
        self.assertEqual(resp, mapping.get_class('Success'))

if __name__ == '__main__':
    unittest.main()
