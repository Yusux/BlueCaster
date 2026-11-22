"""Transport regression tests with no adapter, headphones, or system driver."""

import unittest

from broker import Broker, cmd, complete, completed, status_event
from discovery import advertisements, report

PEER = "01:23:45:67:89:AB"


class Sink:
    def __init__(self):
        self.sent = []

    def on_packet(self, p):
        self.sent.append(p)

    write = on_packet


class RadioTests(unittest.TestCase):
    def setUp(self):
        self.phy = Sink()
        self.b = Broker(self.phy, PEER)
        self.b.radio = Sink()
        self.b.primary = Sink()
        self.b.audio_ready = True
        self.b.address_type = 0

    def test_reset_stays_virtual(self):
        self.assertFalse(self.b.guest_packet(cmd(0xC03)))
        self.assertEqual(self.phy.sent, [])

    def test_acl_ownership(self):
        self.b.handle = 2
        audio = b"\x02\x01\x20\x01\0x"
        guest = b"\x02\x02\x20\x01\0y"
        self.b.guest_packet(audio)
        self.b.guest_packet(guest)
        self.assertEqual(self.phy.sent, [guest])
        self.b.on_packet(audio)
        self.b.on_packet(guest)
        self.assertEqual(self.b.primary.sent, [audio])
        self.assertEqual(self.b.radio.sent, [guest])
        self.b.on_packet(completed([(1, 3), (2, 1)]))
        self.assertEqual(self.b.radio.sent[-1], completed([(2, 1)]))
        self.assertEqual(self.b.primary.sent[-1], completed([(1, 3)]))

    def test_primary_cannot_disconnect_windows_handle(self):
        self.b.handle = 7
        self.b.primary_packet(cmd(0x0406, bytes((7, 0, 19))))
        self.assertFalse(self.phy.sent)
        self.assertEqual(self.b.primary.sent, [status_event(0x0406, 2)])

    def test_raw_legacy_advertisements_roundtrip(self):
        row = bytes.fromhex("00 01 01 02 03 04 05 06 03 02 01 06 c6")
        event = bytes((4, 0x3E, 2 + len(row) * 2, 2, 2)) + row * 2
        single = bytes((4, 0x3E, 2 + len(row), 2, 1)) + row
        self.assertEqual(
            [report(r, False) for r in advertisements(event)], [single, single]
        )
        self.assertEqual(list(advertisements(event[:-1])), [])

    def test_raw_extended_advertisements_roundtrip(self):
        row = bytes.fromhex(
            "13 00 00 06 05 04 03 02 01 01 00 ff 7f c6 00 00 00 00 00 00 00 00 00 03 02 01 06"
        )
        event = bytes((4, 0x3E, 2 + len(row), 13, 1)) + row
        self.assertEqual([report(r, True) for r in advertisements(event)], [event])

    def test_only_selected_peer(self):
        self.b.guest_packet(cmd(0x200D, bytes(25)))
        self.assertFalse(self.phy.sent)
        self.assertEqual(self.b.radio.sent, [status_event(0x200D, 2)])

    def test_legacy_create_on_extended_controller(self):
        self.b.scan_enable = cmd(0x2042, bytes([1, 0, 0, 0, 0, 0]))
        p = bytearray(25)
        p[6:12] = self.b.allowed
        self.b.guest_packet(cmd(0x200D, p))
        self.assertEqual(self.phy.sent, [cmd(0x2042, bytes(6))])
        self.b.on_packet(complete(0x2042))
        self.assertEqual(self.phy.sent[-1][1:3], b"\x43\x20")
        self.b.on_packet(status_event(0x2043, 0))
        self.assertEqual(self.b.radio.sent[-1], status_event(0x200D, 0))
        self.assertFalse(self.b.primary.sent)

    def test_advertising_framing(self):
        r = bytes.fromhex("da 0d 00 01 01 02 03 04 05 06 c6 03 02 01 06")
        self.assertEqual(
            report(r, False),
            bytes.fromhex("04 3e 0f 02 01 00 01 01 02 03 04 05 06 03 02 01 06 c6"),
        )
        self.assertEqual(report(r, True)[3:7], bytes.fromhex("0d 01 13 00"))
        self.assertIsNone(report(r[:-1], False))
