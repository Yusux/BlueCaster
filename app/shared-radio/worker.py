"""Private transport for the BlueCaster core. stdin/stdout carry binary H4.

stderr carries the log, and the worker's state for the core's Adapter screen
as lines "bluecaster-status <state> [detail]" (hci-transport's shared.rs):
waiting (for Windows to attach), attached, connected (the peripheral's link
to Windows is up), error <message>.
"""

import asyncio
import logging
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

from broker import Broker
from bumble.transport import open_transport
from discovery import advertisements, report
from usb_radio import Export


STATUS_PREFIX = "bluecaster-status"


def report(state, detail=""):
    """Tell the core the worker's state (one line on stderr)."""
    line = f"{STATUS_PREFIX} {state} {detail}".rstrip()
    print(line.replace("\n", " "), file=sys.stderr, flush=True)


def read_frame(source):
    kind = source.read(1)
    if not kind:
        return None
    size = {1: 3, 2: 4, 3: 3, 5: 4}[kind[0]]
    header = source.read(size)
    if len(header) != size:
        raise EOFError("partial H4 header")
    payload = int.from_bytes(header[2:], "little")
    if kind == b"\x05":
        payload &= 0x3FFF
    body = source.read(payload)
    if len(body) != payload:
        raise EOFError("partial H4 packet")
    return kind + header + body


class CorePipe:
    def __init__(self, output):
        self.output = output

    def write(self, packet):
        self.output.write(packet)
        self.output.flush()


async def run(adapter, peer, output):
    if not re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{4}", adapter):
        raise ValueError("invalid USB adapter ID")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", peer):
        raise ValueError("invalid BLE peripheral address")
    usbip = (
        Path(
            os.environ["ProgramW6432"]
            if "ProgramW6432" in os.environ
            else os.environ["ProgramFiles"]
        )
        / "USBip/usbip.exe"
    )
    if not usbip.is_file():
        raise RuntimeError(
            "shared radio requires the signed usbip-win2 controller and USBip client"
        )

    async with await open_transport("usb:" + adapter) as physical:
        broker = Broker(physical.sink, peer)
        broker.primary = CorePipe(output)
        export = Export(broker)
        broker.on_state = lambda s: report("connected" if s == "connected" else "attached")
        export.on_state = lambda s: report("attached" if s == "attached" else "waiting")

        class PhysicalEvents:
            def on_packet(self, packet):
                for event in advertisements(packet):
                    ext = event[0] == 0xDB
                    start = 5 if ext else 4
                    if event[start : start + 6] != broker.allowed:
                        continue
                    broker.address_type = event[start - 1]
                    radio = export.radio
                    if radio and radio.controller.le_scan_enable:
                        converted = report(event, radio.extended_scan)
                        if converted:
                            radio.on_packet(converted)
                broker.on_packet(packet)

        physical.source.set_packet_sink(PhysicalEvents())
        async with await asyncio.start_server(export.client, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]

            async def attach():
                while not broker.bd_addr:
                    await asyncio.sleep(0.05)
                proc = await asyncio.create_subprocess_exec(
                    str(usbip),
                    "-t",
                    str(port),
                    "attach",
                    "-r",
                    "127.0.0.1",
                    "-b",
                    "1-1",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                try:
                    _, error = await asyncio.wait_for(proc.communicate(), 15)
                    if proc.returncode:
                        raise RuntimeError(
                            "USB/IP attach failed: "
                            + error.decode(errors="replace").strip()
                        )
                finally:
                    if proc.returncode is None:
                        proc.kill()
                        await proc.wait()

            # The blocking Windows anonymous pipe has no overlapped handle.
            # Read on one daemon thread and deliver frames in order on the loop.
            loop = asyncio.get_running_loop()
            finished = loop.create_future()

            def finish(error=None):
                if not finished.done():
                    if error is None:
                        finished.set_result(None)
                    else:
                        finished.set_exception(error)

            def dispatch(packet):
                try:
                    broker.primary_packet(packet)
                except Exception as error:
                    finish(error)

            def read_core():
                try:
                    while (packet := read_frame(sys.stdin.buffer)) is not None:
                        loop.call_soon_threadsafe(dispatch, packet)
                except Exception as error:
                    loop.call_soon_threadsafe(finish, error)
                else:
                    loop.call_soon_threadsafe(finish)

            threading.Thread(target=read_core, daemon=True).start()
            report("waiting")
            attachment = asyncio.create_task(attach())
            try:
                await asyncio.wait(
                    (finished, attachment), return_when=asyncio.FIRST_COMPLETED
                )
                if attachment.done():
                    await attachment
                await finished
            finally:
                attachment.cancel()
                await asyncio.gather(attachment, return_exceptions=True)
                if export.radio:
                    export.radio.writer.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Keep stdout exclusively for H4, including prints from dependencies.
    output = sys.stdout.buffer
    sys.stdout = sys.stderr
    try:
        asyncio.run(run(*sys.argv[1:], output))
    except Exception as error:
        report("error", str(error) or type(error).__name__)
        raise
