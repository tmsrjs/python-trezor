import unittest
import common
import binascii

from trezorlib import mapping
from trezorlib.messages import OutputScriptType
from trezorlib.messages.TxInputType import TxInputType

class TestMsgEstimatetxsize(common.TrezorTest):
    def test_estimate_size(self):
        self.setup_mnemonic_nopin_nopassphrase()

        raise Exception("TxInputType nema wire type!!")
        inp1 = TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        out1 = mapping.get_class('TxOutputType')(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                              amount=390000 - 10000,
                              script_type=OutputScriptType.PAYTOADDRESS,
                              )


        est_size = self.client.estimate_tx_size('Bitcoin', [inp1, ], [out1, ])
        self.assertEqual(est_size, 194)

        (_, tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        real_size = len(tx)

        self.assertGreaterEqual(est_size, real_size)

if __name__ == '__main__':
    unittest.main()
