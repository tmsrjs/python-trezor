import time
import unittest
import common

from trezorlib import mapping

Initialize = mapping.get_class('Initialize')
Ping = mapping.get_class('Ping')
PinMatrixRequest = mapping.get_class('PinMatrixRequest')
PinMatrixAck = mapping.get_class('PinMatrixAck')
ChangePin = mapping.get_class('ChangePin')
Success = mapping.get_class('Success')
ButtonAck = mapping.get_class('ButtonAck')
ButtonRequest = mapping.get_class('ButtonRequest')
Cancel = mapping.get_class('Cancel')
Failure = mapping.get_class('Failure')

class TestMsgChangepin(common.TrezorTest):

    def test_set_pin(self):
        self.setup_mnemonic_nopin_nopassphrase()
        features = self.client.call_raw(Initialize())
        self.assertFalse(features.pin_protection)

        # Check that there's no PIN protection
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, Success)

        # Let's set new PIN
        ret = self.client.call_raw(ChangePin())
        self.assertEqual(ret, ButtonRequest)

        # Press button
        self.client.debug.press_yes()
        ret = self.client.call_raw(ButtonAck())

        # Send the PIN for first time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send the PIN for second time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Now we're done
        self.assertEqual(ret, Success)

        # Check that there's PIN protection now
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, PinMatrixRequest)
        self.client.call_raw(Cancel())

        # Check that the PIN is correct
        self.assertEqual(self.client.debug.read_pin()[0], self.pin6)

    def test_change_pin(self):
        self.setup_mnemonic_pin_passphrase()
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)

        # Check that there's PIN protection
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, PinMatrixRequest)
        self.client.call_raw(Cancel())

        # Check current PIN value
        self.assertEqual(self.client.debug.read_pin()[0], self.pin4)

        # Let's change PIN
        ret = self.client.call_raw(ChangePin())
        self.assertEqual(ret, ButtonRequest)

        # Press button
        self.client.debug.press_yes()
        ret = self.client.call_raw(ButtonAck())

        # Send current PIN
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.read_pin_encoded()
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send new PIN for first time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send the PIN for second time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Now we're done
        self.assertEqual(ret, Success)

        # Check that there's still PIN protection now
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, PinMatrixRequest)
        self.client.call_raw(Cancel())

        # Check that the PIN is correct
        self.assertEqual(self.client.debug.read_pin()[0], self.pin6)

    def test_remove_pin(self):
        self.setup_mnemonic_pin_passphrase()
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)

        # Check that there's PIN protection
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, PinMatrixRequest)
        self.client.call_raw(Cancel())

        # Let's remove PIN
        ret = self.client.call_raw(ChangePin(remove=True))
        self.assertEqual(ret, ButtonRequest)

        # Press button
        self.client.debug.press_yes()
        ret = self.client.call_raw(ButtonAck())

        # Send current PIN
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.read_pin_encoded()
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Now we're done
        self.assertEqual(ret, Success)

        # Check that there's no PIN protection now
        features = self.client.call_raw(Initialize())
        self.assertFalse(features.pin_protection)
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, Success)

    def test_set_failed(self):
        self.setup_mnemonic_nopin_nopassphrase()
        features = self.client.call_raw(Initialize())
        self.assertFalse(features.pin_protection)

        # Check that there's no PIN protection
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, Success)

        # Let's set new PIN
        ret = self.client.call_raw(ChangePin())
        self.assertEqual(ret, ButtonRequest)

        # Press button
        self.client.debug.press_yes()
        ret = self.client.call_raw(ButtonAck())

        # Send the PIN for first time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send the PIN for second time, but with typo
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin4)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Now it should fail, because pins are different
        self.assertEqual(ret, Failure)

        # Check that there's still no PIN protection now
        features = self.client.call_raw(Initialize())
        self.assertFalse(features.pin_protection)
        ret = self.client.call_raw(Ping(pin_protection=True))
        self.assertEqual(ret, Success)

    def test_set_failed_2(self):
        self.setup_mnemonic_pin_passphrase()
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)

        # Let's set new PIN
        ret = self.client.call_raw(ChangePin())
        self.assertEqual(ret, ButtonRequest)

        # Press button
        self.client.debug.press_yes()
        ret = self.client.call_raw(ButtonAck())

        # Send current PIN
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.read_pin_encoded()
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send the PIN for first time
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Send the PIN for second time, but with typo
        self.assertEqual(ret, PinMatrixRequest)
        pin_encoded = self.client.debug.encode_pin(self.pin6 + '3')
        ret = self.client.call_raw(PinMatrixAck(pin=pin_encoded))

        # Now it should fail, because pins are different
        self.assertEqual(ret, Failure)

        # Check that there's still old PIN protection
        features = self.client.call_raw(Initialize())
        self.assertTrue(features.pin_protection)
        self.assertEqual(self.client.debug.read_pin()[0], self.pin4)

if __name__ == '__main__':
    unittest.main()
