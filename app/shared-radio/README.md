# Windows BLE sharing (experimental)

In developer mode, the BlueCaster Adapter screen can reserve one Bluetooth LE peripheral for Windows while the classic audio stack owns the physical WinUSB adapter. Select the adapter, enter the peripheral's Bluetooth address and save. Start a new classic connection and pair the peripheral in Windows Settings. Clear the address and save to return to ordinary audio on the next connection. Existing profiles use ordinary audio by default. Once an address is saved, the section stays on the Adapter screen without developer mode, so sharing can be turned off.

The section shows where sharing is: not running (it starts with the next classic connection), starting, waiting for Windows (the virtual controller is not attached yet: usually usbip-win2 is missing), ready (pair or connect the peripheral in Windows), connected, or stopped with the worker's error. The worker reports these as `bluecaster-status <state> [detail]` lines on stderr (`worker.py`); `hci-transport/src/shared.rs` parses them for `AdapterState::shared_radio`.

The Windows machine needs the signed usbip-win2 virtual host controller and its client in the default USBip installation directory. Installing BlueCaster does not change the Windows kernel driver configuration. Users install the regular BlueCaster package and use the existing core and UI.

The core starts its private H4 worker for the lifetime of the shared transport. The two processes exchange H4 frames over inherited pipes. Windows attaches through USB/IP on an ephemeral loopback port once the radio's public address is known. The Intel USB loader runs on the original transport before the shared worker claims the adapter. Windows owns at most one BLE connection. Classic Bluetooth peripherals, rotating peripheral addresses, LE Audio sharing, headset microphone audio and multiple physical adapters with identical USB IDs are outside the tested configuration.

## Build and test

A release build packages the pinned Python runtime and worker dependencies using uv. From the repository root, use `pwsh ./build.ps1 -SharedRadio` for a local build with the worker or `pwsh ./build.ps1 -Release -Arch x64` for the regular installer. Users do not need uv or a system Python installation. The worker runs on x64 Windows. ARM64 hosts running the x64 worker have not been tested.

Run `python -m unittest discover -s app/shared-radio` for hardware-independent packet routing and advertisement tests. Hardware validation needs a controller on WinUSB, firmware for the controller, a classic audio receiver and a BLE peripheral. Verify the chosen audio codec in BlueCaster and read actual peripheral input in Windows. Validate cold startup, disconnect/reconnect and disabling sharing separately.
