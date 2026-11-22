"""Local USB/IP Bluetooth controller for the Windows inbox BTHUSB driver."""

import asyncio
import logging
import struct
from collections import deque

from winvhci.bumble_compat import (
    WindowsCompatController,
    WindowsCompatLink,
    apply_dual_mode,
)

BUSID = b"1-1"
VID, PID = 0x1209, 0xBC03  # local experimental device only
DEVICE = struct.pack(
    "<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xE0, 1, 1, 64, VID, PID, 0x0100, 1, 2, 3, 1
)
# Bluetooth HCI over USB: interrupt IN, bulk OUT/IN; idle SCO interface.
CONFIG = bytes.fromhex(
    "09 02 30 00 02 01 00 80 32 "
    "09 04 00 00 03 e0 01 01 00 "
    "07 05 81 03 10 00 01 07 05 02 02 40 00 00 "
    "07 05 82 02 40 00 00 09 04 01 00 00 e0 01 01 00"
)
# BTHUSB selects an isochronous alternate during enumeration, even for LE.
interfaces = CONFIG[9:-9] + b"".join(
    bytes([9, 4, 1, alt, 2, 0xE0, 1, 1, 0])
    + b"".join(struct.pack("<BBBBHB", 7, 5, ep, 1, size, 1) for ep in (3, 0x83))
    for alt, size in enumerate((0, 9, 17, 25, 33, 49, 63))
)
CONFIG = (
    struct.pack("<BBHBBBBB", 9, 2, 9 + len(interfaces), 2, 1, 0, 0xA0, 50) + interfaces
)
STRINGS = [
    "",
    "BlueCaster local development",
    "BlueCaster Shared Bluetooth",
    "BCST0001",
]
RECORD = struct.pack(
    ">256s32sIIIHHHBBBBBB",
    b"/local/bluecaster",
    BUSID,
    1,
    1,
    2,
    VID,
    PID,
    0x0100,
    0xE0,
    1,
    1,
    1,
    1,
    2,
)
HEADER = struct.Struct(">IIIII")
SUBMIT, UNLINK, RET_SUBMIT, RET_UNLINK = 1, 2, 3, 4
LOG = logging.getLogger("usb-radio")


class Radio:
    def __init__(self, writer, broker):
        self.broker = broker
        self.writer = writer
        self.pending = {1: deque(), 2: deque()}
        self.packets = {1: deque(), 2: deque()}
        self.controller = WindowsCompatController(
            "BlueCaster",
            link=WindowsCompatLink(),
            host_sink=self,
            public_address="02:BC:03:00:00:01",
        )
        apply_dual_mode(self.controller)
        self.extended_scan = False
        if broker:
            broker.radio = self
            self.controller.total_num_le_acl_data_packets = 1
            self.controller.total_num_acl_data_packets = 1

    def on_packet(self, packet):
        ep = {4: 1, 2: 2}.get(packet[0])
        if ep is None:
            return
        if len(self.packets[ep]) >= 128:
            # Only advertising reports can be dropped when Windows is busy.
            if packet[:2] == b"\x04\x3e" and packet[3:4] in (b"\x02", b"\x0d"):
                return
            raise ConnectionError("Windows stopped consuming controller events")
        self.packets[ep].append(packet[1:])
        self.flush(ep)

    def flush(self, ep):
        while self.pending[ep] and self.packets[ep]:
            seq, size = self.pending[ep].popleft()
            data = self.packets[ep].popleft()
            if len(data) > size:
                self.packets[ep].appendleft(data[size:])
            self.reply(seq, data[:size])

    def reply(self, seq, data=b"", status=0, out_length=0):
        self.writer.write(
            HEADER.pack(RET_SUBMIT, seq, 0, 0, 0)
            + struct.pack(">iiiii8x", status, len(data) or out_length, 0, 0, 0)
            + data
        )

    def control(self, seq, setup, payload):
        typ, req, value, index, size = struct.unpack("<BBHHH", setup)
        LOG.debug(
            "control %02x %02x value=%04x idx=%04x size=%d",
            typ,
            req,
            value,
            index,
            size,
        )
        if typ in (0x20, 0x21) and req == 0:
            if len(payload) < 3 or len(payload) != 3 + payload[2]:
                return self.reply(seq, status=-32)
            LOG.debug("Windows command %04x", int.from_bytes(payload[:2], "little"))
            op = int.from_bytes(payload[:2], "little")
            if op in (0x200C, 0x2042):
                self.extended_scan = op == 0x2042
            packet = b"\x01" + payload
            if self.broker and op == 0x1009 and self.broker.bd_addr:
                self.on_packet(b"\x04\x0e\x0a\x01\x09\x10\x00" + self.broker.bd_addr)
            elif not self.broker or not self.broker.guest_packet(packet):
                self.controller.on_packet(packet)
            return self.reply(seq, out_length=len(payload))
        if typ == 0x80 and req == 6:
            kind, n = divmod(value, 256)
            data = {1: DEVICE, 2: CONFIG}.get(kind)
            if kind == 3 and n < len(STRINGS):
                body = STRINGS[n].encode("utf-16-le") if n else b"\x09\x04"
                data = bytes([len(body) + 2, 3]) + body
            if data is not None:
                return self.reply(seq, data[:size])
        if (typ, req) in ((0, 9), (1, 11), (2, 1)):
            return self.reply(seq)
        if req == 0 and typ in (0x80, 0x81, 0x82):
            return self.reply(seq, b"\x00\x00"[:size])
        if (typ, req) in ((0x80, 8), (0x81, 10)):
            return self.reply(seq, bytes([int(req == 8)])[:size])
        self.reply(seq, status=-32)

    async def run(self, reader):
        while True:
            header = await reader.readexactly(48)
            cmd, seq, _, direction, ep = HEADER.unpack_from(header)
            if cmd == UNLINK:
                target = struct.unpack_from(">I", header, 20)[0]
                cancelled = False
                for queue in self.pending.values():
                    for item in list(queue):
                        if item[0] == target:
                            queue.remove(item)
                            cancelled = True
                self.writer.write(
                    HEADER.pack(RET_UNLINK, seq, 0, 0, 0)
                    + struct.pack(">i24x", -104 if cancelled else 0)
                )
                continue
            if cmd != SUBMIT:
                raise ValueError("unknown USB/IP operation")
            length = struct.unpack_from(">i", header, 24)[0]
            if not 0 <= length <= 65536 or direction not in (0, 1):
                raise ValueError("invalid USB/IP submit")
            payload = await reader.readexactly(length) if direction == 0 else b""
            if ep == 0:
                self.control(seq, header[40:48], payload)
            elif direction and ep in self.pending and length:
                if len(self.pending[ep]) >= 128:
                    raise ValueError("excess queued reads")
                self.pending[ep].append((seq, length))
                self.flush(ep)
            elif direction == 0 and ep == 2:
                LOG.debug("USB ACL OUT len=%d", length)
                packet = b"\x02" + payload
                if not self.broker or not self.broker.guest_packet(packet):
                    self.controller.on_packet(packet)
                self.reply(seq, out_length=length)
            else:
                self.reply(seq, status=-32)
            await self.writer.drain()


class Export:
    def __init__(self, broker=None):
        self.broker = broker
        self.radio = None
        # Told "attached" / "detached" when Windows imports the virtual
        # controller or lets it go
        self.on_state = lambda state: None

    async def client(self, reader, writer):
        radio = None
        try:
            version, op, status = struct.unpack(">HHI", await reader.readexactly(8))
            if version != 0x111 or status:
                return
            if op == 0x8005:
                writer.write(
                    struct.pack(">HHII", version, 5, 0, 1)
                    + RECORD
                    + bytes.fromhex("e0 01 01 00 e0 01 01 00")
                )
            elif op == 0x8003:
                bus = (await reader.readexactly(32)).rstrip(b"\0")
                if self.radio or bus != BUSID:
                    writer.write(struct.pack(">HHI", version, 3, 1))
                else:
                    radio = self.radio = Radio(writer, self.broker)
                    writer.write(struct.pack(">HHI", version, 3, 0) + RECORD)
                    await writer.drain()
                    LOG.info("Windows imported the virtual controller")
                    self.on_state("attached")
                    await radio.run(reader)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            if radio is not None:
                if self.broker:
                    self.broker.radio = None
                    self.broker.guest_closed()
                self.radio = None
                self.on_state("detached")
            writer.close()
