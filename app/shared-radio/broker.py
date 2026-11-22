"""Arbitrate one physical controller between classic audio and a Windows BLE central.

The virtual controller handles Windows initialization locally. Only an explicit
peripheral can be connected. Physical ACL handles never overlap because one
controller allocates them; every event/data path is classified before delivery.
"""

import logging
import struct
from collections import deque

LOG = logging.getLogger("shared-hci")


def u16(data, pos):
    return int.from_bytes(data[pos : pos + 2], "little")


def complete(op, status=0):
    return b"\x04\x0e\x04\x01" + struct.pack("<H", op) + bytes([status])


def status_event(op, status):
    return b"\x04\x0f\x04" + bytes([status, 1]) + struct.pack("<H", op)


def cmd(op, params=b""):
    return b"\x01" + struct.pack("<HB", op, len(params)) + params


def completed(items):
    params = bytes([len(items)]) + b"".join(struct.pack("<HH", h, n) for h, n in items)
    return bytes([4, 0x13, len(params)]) + params


# Commands whose first argument is a connection handle; physical writes
# are accepted only on the Windows-owned link.
LINK_COMMANDS = {
    0x0406,
    0x041D,
    0x1405,
    0x1408,
    0x1403,
    0x2013,
    0x2016,
    0x2019,
    0x201A,
    0x201B,
    0x2020,
    0x2021,
    0x2022,
    0x2030,
    0x2032,
}
ASYNC_COMMANDS = {0x0406, 0x041D, 0x2013, 0x2016, 0x2019, 0x2032}
CREATE = {0x200D, 0x2043}


class Broker:
    def __init__(self, physical, allowed_address):
        self.physical = physical
        self.allowed = bytes.fromhex(allowed_address.replace(":", ""))[::-1]
        self.primary = None
        self.radio = None
        self.cmdq = deque()
        self.inflight = None
        self.credits = 1
        self.handle = None
        self.connecting = False
        self.address_type = None
        self.bd_addr = None
        self.random_address = None
        self.audio_ready = False
        self.scan_enable = None
        self.resume_scan = None
        self.create_alias = None
        self.guest_le_mask = 0
        self.accept_list = set()
        self.guest_packets = 0
        self.in_packets = 0
        # Told "connected" / "disconnected" when the selected peripheral's
        # link to Windows comes up or ends
        self.on_state = lambda state: None

    @staticmethod
    def log_acl(direction, n, p):
        if n <= 100 and LOG.isEnabledFor(logging.DEBUG):
            start = (p[2] >> 4) & 3 != 1
            LOG.debug(
                "ACL %s #%d len=%d cid=%s op=%s",
                direction,
                n,
                len(p) - 5,
                u16(p, 7) if start and len(p) >= 9 else "-",
                hex(p[9]) if start and len(p) > 9 else "-",
            )

    def set_packet_sink(self, sink):
        self.physical = sink

    def primary_out(self, packet):
        if self.primary is not None:
            self.primary.write(packet)

    def guest_out(self, packet):
        if self.radio is not None:
            self.radio.on_packet(packet)

    def queue(self, origin, packet):
        if len(self.cmdq) >= 128:
            raise ConnectionError("physical command queue is full")
        self.cmdq.append((origin, packet))
        self.pump()

    def pump(self):
        if not self.cmdq or self.inflight is not None or not self.credits:
            return
        origin, packet = self.cmdq.popleft()
        self.inflight = (origin, u16(packet, 1))
        self.credits -= 1
        self.physical.on_packet(packet)

    def primary_packet(self, packet):
        if packet[0] == 1:
            op = u16(packet, 1)
            if (
                op in LINK_COMMANDS
                and self.handle is not None
                and (u16(packet, 4) & 0xFFF) == self.handle
            ):
                reply = status_event if op in ASYNC_COMMANDS else complete
                self.primary_out(reply(op, 0x02))
                return
            if op in (0x200C, 0x2042):
                self.scan_enable = packet
            if op == 0x0C03:
                self.audio_ready = False
                if self.handle is not None:
                    self.guest_out(
                        b"\x04\x05\x04\x00" + struct.pack("<H", self.handle) + b"\x16"
                    )
                self.handle = None
                self.connecting = False
            self.queue("primary", packet)
        elif packet[0] in (2, 3, 5):
            if self.handle is None or (u16(packet, 1) & 0xFFF) != self.handle:
                self.physical.on_packet(packet)

    def deny(self, op, code=0x0C):
        self.guest_out(
            status_event(op, code)
            if op in CREATE | ASYNC_COMMANDS
            else complete(op, code)
        )

    def guest_packet(self, packet):
        """True when the physical broker consumed this packet."""
        if packet[0] == 2:
            if self.handle is not None and (u16(packet, 1) & 0xFFF) == self.handle:
                self.physical.on_packet(packet)
                self.guest_packets += 1
                self.log_acl("to peer", self.guest_packets, packet)
            return True
        if packet[0] != 1:
            return False
        op, p = u16(packet, 1), packet[4:]
        if op in (0x0405, 0x0419):
            # BR/EDR belongs to the audio host. Windows may page old paired
            # devices as soon as it recognizes the real radio address.
            self.guest_out(status_event(op, 0x0C))
            return True
        if op == 0x0C03:
            self.guest_closed()
            return False
        if op == 0x2005:
            self.random_address = p
            return False
        if op == 0x2001:
            self.guest_le_mask = int.from_bytes(p, "little")
        if op == 0x2010:
            self.accept_list.clear()
        if op in (0x2011, 0x2012) and len(p) == 7:
            if op == 0x2011:
                self.accept_list.add(p[1:])
            else:
                self.accept_list.discard(p[1:])
        if op in CREATE:
            if self.connecting or self.handle is not None or not self.audio_ready:
                self.deny(op)
                return True
            # Both forms are rewritten to a single explicit peer. Never
            # inherit the physical controller's accept or resolving lists.
            params = bytearray(p)
            if op == 0x200D and len(p) == 25:
                filt, peer_type, addr, own = 4, 5, 6, 12
            elif op == 0x2043 and len(p) >= 26:
                filt, own, peer_type, addr = 0, 1, 2, 3
            else:
                self.deny(op, 0x12)
                return True
            if (
                (params[filt] and self.allowed not in self.accept_list)
                or (not params[filt] and params[addr : addr + 6] != self.allowed)
                or self.address_type is None
            ):
                self.deny(op, 0x02)
                return True
            params[filt] = 0
            params[addr : addr + 6] = self.allowed
            params[peer_type] = self.address_type
            # Use the same public identity Windows learned at Read BD_ADDR.
            # Its private address cannot be shared with the primary host.
            enabled = self.scan_enable
            if params[own] and self.random_address is None:
                self.deny(op)
                return True
            if enabled and enabled[4]:
                self.resume_scan = enabled
                self.queue("internal", cmd(u16(enabled, 1), bytes(len(enabled) - 4)))
            if params[own] != 0:
                self.queue("internal", cmd(0x2005, self.random_address))
                params[own] = 1
            self.connecting = True
            LOG.info("Windows requested connection to selected peripheral")
            physical_op = op
            if enabled and u16(enabled, 1) == 0x2042 and op == 0x200D:
                # Intel disallows mixing legacy and extended procedures in
                # the same reset epoch. Preserve timing on the 1M PHY.
                params = (
                    bytes([0, params[12], params[5]])
                    + params[6:12]
                    + bytes([1])
                    + params[:4]
                    + params[13:]
                )
                physical_op = 0x2043
            elif enabled and u16(enabled, 1) == 0x200C and op == 0x2043:
                if not params[9] & 1:
                    self.connecting = False
                    self.deny(op, 0x11)
                    self.restore_scan()
                    return True
                params = (
                    params[10:14]
                    + bytes([0, params[2]])
                    + params[3:9]
                    + bytes([params[1]])
                    + params[14:26]
                )
                physical_op = 0x200D
            # Leave scheduling room for BR/EDR. Windows initially asks for a
            # fixed 7.5 ms interval; the peripheral can negotiate a faster
            # interval once link encryption and service discovery complete.
            params = bytearray(params)
            offset = 14 if physical_op == 0x2043 else 13
            if u16(params, offset + 2) < 12:
                struct.pack_into("<HH", params, offset, 12, 24)
            self.create_alias = op
            LOG.debug(
                "LE create Windows=%04x controller=%04x timing=%s",
                op,
                physical_op,
                bytes(params[-16:]).hex(),
            )
            self.queue("guest", cmd(physical_op, params))
            return True
        if op == 0x200E and self.connecting:
            self.queue("guest", packet)
            return True
        if op in LINK_COMMANDS:
            LOG.debug("Windows link command %04x", op)
            if self.handle is None or len(p) < 2 or (u16(p, 0) & 0xFFF) != self.handle:
                self.deny(op, 0x02)
            else:
                self.queue("guest", packet)
            return True
        return False

    def restore_scan(self):
        if self.resume_scan:
            packet, self.resume_scan = self.resume_scan, None
            self.queue("internal", packet)

    def guest_closed(self):
        if self.connecting:
            self.queue("internal", cmd(0x200E))
        if self.handle is not None:
            self.queue("internal", cmd(0x0406, struct.pack("<HB", self.handle, 0x13)))

    def on_packet(self, packet):
        if packet[0] == 2:
            if self.handle is not None and (u16(packet, 1) & 0xFFF) == self.handle:
                self.in_packets += 1
                self.log_acl("from peer", self.in_packets, packet)
                self.guest_out(packet)
            else:
                self.primary_out(packet)
            return
        if packet[0] != 4 or len(packet) < 3:
            self.primary_out(packet)
            return
        ev = packet[1]
        if self.handle is not None and ev in (5, 8, 12, 0x30, 0x59, 0x3E):
            if ev != 0x3E or packet[3] not in (2, 13):
                LOG.debug("controller event %02x sub/status=%02x", ev, packet[3])
        if ev in (0x0E, 0x0F) and len(packet) >= 7:
            op = u16(packet, 4 if ev == 0x0E else 5)
            self.credits = packet[3 if ev == 0x0E else 4]
            if self.inflight is not None and self.inflight[1] == op:
                origin, _ = self.inflight
                self.inflight = None
                status = packet[6 if ev == 0x0E else 3]
                if origin == "guest" and op in CREATE and self.create_alias:
                    packet = status_event(self.create_alias, status)
                    self.create_alias = None
                if origin == "guest":
                    LOG.debug("controller response %04x status=%02x", op, status)
                if origin == "internal" and status:
                    LOG.warning(
                        "controller management command %04x returned %02x", op, status
                    )
                if origin == "guest" and op in CREATE and status:
                    LOG.info("LE connection command refused with 0x%02x", status)
                    self.connecting = False
                    self.restore_scan()
                if op == 0x1009 and not status and len(packet) >= 13:
                    self.bd_addr = packet[7:13]
                    self.audio_ready = True
                if (
                    origin == "primary"
                    and op == 0x1005
                    and not status
                    and len(packet) >= 14
                ):
                    # Reserve one physical ACL credit for Windows (Intel
                    # shares its BR/EDR pool with LE when LE buffers = 0).
                    count = u16(packet, 10)
                    if count >= 2:
                        packet = (
                            packet[:10] + struct.pack("<H", count - 1) + packet[12:]
                        )
                if origin == "primary":
                    self.primary_out(packet)
                elif origin == "guest":
                    self.guest_out(packet)
                self.pump()
                return
        if ev == 0x13 and len(packet) >= 4 and len(packet) == 4 + packet[3] * 4:
            items = list(struct.iter_unpack("<HH", packet[4:]))
            for target, sink in [(True, self.guest_out), (False, self.primary_out)]:
                part = [
                    (h, n) for h, n in items if (((h & 0xFFF) == self.handle) == target)
                ]
                if part:
                    sink(completed(part))
            return
        if ev == 0x3E and len(packet) >= 5:
            sub = packet[3]
            if sub in (1, 10) and self.connecting and len(packet) >= 15:
                if packet[4] or packet[9:15] == self.allowed:
                    self.connecting = False
                    if not packet[4]:
                        self.handle = u16(packet, 5) & 0xFFF
                        LOG.info("Windows LE connection established")
                        self.on_state("connected")
                    else:
                        LOG.info(
                            "Windows LE connection failed with status 0x%02x", packet[4]
                        )
                    if (
                        sub == 10
                        and not self.guest_le_mask & (1 << 9)
                        and len(packet) >= 34
                    ):
                        # V1 enhanced completion carries two extra RPAs.
                        packet = bytes([4, 0x3E, 19, 1]) + packet[4:15] + packet[27:34]
                    self.guest_out(packet)
                    if packet[4]:
                        self.restore_scan()
                    return
            # Most LE link events have status before their handle. LTK
            # request, remote parameter request and data length change do not.
            pos = {3: 5, 4: 5, 5: 4, 6: 4, 7: 4, 12: 5, 20: 4}.get(sub)
            if (
                pos is not None
                and self.handle is not None
                and (u16(packet, pos) & 0xFFF) == self.handle
            ):
                self.guest_out(packet)
                return
        if (
            ev in (0x05, 0x08, 0x0C, 0x30, 0x59)
            and len(packet) >= 6
            and self.handle is not None
        ):
            if (u16(packet, 4) & 0xFFF) == self.handle:
                if ev == 0x59 and len(packet) == 8:
                    # Windows configures the emulated HCI 5.0 interface.
                    # Intel uses Encryption Change v2 (5.3) on its own mask.
                    packet = bytes([4, 8, 4]) + packet[3:7]
                self.guest_out(packet)
                if ev == 5:
                    self.restore_scan()
                    LOG.info("Windows LE connection ended, reason 0x%02x", packet[6])
                    self.handle = None
                    self.on_state("disconnected")
                return
        self.primary_out(packet)
