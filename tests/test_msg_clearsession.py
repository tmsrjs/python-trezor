import time
import unittest
import common

from trezorlib import mapping
from trezorlib.messages import ButtonRequestType

ButtonRequest = mapping.get_class('ButtonRequest')
PinMatrixRequest = mapping.get_class('PinMatrixRequest')
Success = mapping.get_class('Success')
PassphraseRequest = mapping.get_class('PassphraseRequest')

class TestMsgClearsession(common.TrezorTest):

    def test_clearsession(self):
        self.setup_mnemonic_pin_passphrase()

        with self.client:
            self.client.set_expected_responses([ButtonRequest(code=ButtonRequestType.ProtectCall), PinMatrixRequest(), PassphraseRequest(), Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            # pin and passphrase are cached
            self.client.set_expected_responses([ButtonRequest(code=ButtonRequestType.ProtectCall), Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

        self.client.clear_session()

        # session cache is cleared
        with self.client:
            self.client.set_expected_responses([ButtonRequest(code=ButtonRequestType.ProtectCall), PinMatrixRequest(), PassphraseRequest(), Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            # pin and passphrase are cached
            self.client.set_expected_responses([ButtonRequest(code=ButtonRequestType.ProtectCall), Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

if __name__ == '__main__':
    unittest.main()
