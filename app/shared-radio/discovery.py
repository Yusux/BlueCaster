"""Convert BTstack discovery events to the report format requested by Windows."""

LEGACY_TO_EXT = (0x13, 0x15, 0x12, 0x10, 0x1B)


def report(event, extended):
    if len(event) < 2 or event[1] != len(event) - 2:
        return None
    if event[0] == 0xDA and len(event) >= 12 and len(event) == 12 + event[11]:
        kind, address, rssi, data = event[2], event[3:10], event[10], event[12:]
        if kind >= len(LEGACY_TO_EXT) or len(data) > 31:
            return None
        ext_type = LEGACY_TO_EXT[kind]
        ext_body = bytes((1, 0, 0xFF, 0x7F, rssi)) + bytes(9)
    elif event[0] == 0xDB and len(event) >= 26 and len(event) == 26 + event[25]:
        ext_type = int.from_bytes(event[2:4], "little")
        address, ext_body, rssi, data = event[4:11], event[11:25], event[15], event[26:]
        if not extended and (not ext_type & 0x10 or len(data) > 31):
            return None
        kind = (
            4
            if ext_type & 8
            else 1
            if ext_type & 4
            else 0
            if ext_type & 1
            else 2
            if ext_type & 2
            else 3
        )
    else:
        return None
    body = (
        bytes((13, 1))
        + ext_type.to_bytes(2, "little")
        + address
        + ext_body
        + bytes((len(data),))
        + data
        if extended
        else bytes((2, 1, kind)) + address + bytes((len(data),)) + data + bytes((rssi,))
    )
    return bytes((4, 0x3E, len(body))) + body if len(body) <= 255 else None


def advertisements(packet):
    """Split a physical LE Meta event into the individual BTstack-format reports."""
    if len(packet) < 5 or packet[:2] != b"\x04\x3e" or len(packet) != packet[2] + 3:
        return
    kind, count = packet[3:5]
    if kind not in (2, 13):
        return
    offset = 5
    for _ in range(count):
        ext = kind == 13
        prefix = 24 if ext else 9
        if len(packet) < offset + prefix:
            return
        size = packet[offset + prefix - 1]
        end = offset + prefix + size + (0 if ext else 1)
        if end > len(packet):
            return
        body = packet[offset:end]
        if ext:
            yield bytes((0xDB, len(body))) + body
        else:
            yield bytes((0xDA, len(body))) + body[:8] + body[-1:] + body[8:-1]
        offset = end
