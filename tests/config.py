from __future__ import print_function

import sys
sys.path = ['../',] + sys.path

from trezorlib.transport_udp import UdpTransport
from trezorlib.transport_hid import HidTransport

devices = HidTransport.enumerate()

if len(devices) > 0 and devices[0][1] != None:
    print('Using TREZOR')
    TRANSPORT = HidTransport
    TRANSPORT_ARGS = (devices[0],)
    TRANSPORT_KWARGS = {'debug_link': False}
    DEBUG_TRANSPORT = HidTransport
    DEBUG_TRANSPORT_ARGS = (devices[0],)
    DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
else:
    print('Using TREZOR Core Emulator')
    TRANSPORT = UdpTransport
    TRANSPORT_ARGS = (None,)
    TRANSPORT_KWARGS = {}
    DEBUG_TRANSPORT = UdpTransport
    DEBUG_TRANSPORT_ARGS = (21325,)
    DEBUG_TRANSPORT_KWARGS = {}
