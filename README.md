# growtopia-mitm-proxy

A man-in-the-middle proxy for inspecting Growtopia's client↔server traffic. It sits
between the game client and the server and reconstructs the game's undocumented binary
protocol from captured packets.

> [!WARNING]
> **Work in progress — not functional end to end yet.**
> The current blocker is **obtaining the decryption key** for the encrypted transport,
> so full plaintext capture over the wire isn't working yet. See [Status](#status).

## How it works

Two halves that talk to each other over a local UDP channel:

- **`MyProject_DLL/`** — a DLL injected into `Growtopia.exe`. It hooks the Winsock calls
  (`connect`, `sendto`, `recv`, …) to route the client's traffic through the local proxy,
  and additionally hooks ENet internally (`Enethook.h`, via [MinHook]) to read packets
  *before* they hit the encrypted transport. Captured frames are forwarded to the
  launcher as `"PTXT" + direction + length + data`.
- **`MyProject_GUI/`** — the launcher / analyzer. It injects the DLL, listens for the
  captured frames, and decodes them. `PacketAnalyzer.h` maps the Growtopia message and
  game-packet types (`GT_MSG_*`, `GT_PKT_*`) into a readable view.

## Status

- [x] DLL injection into the game client
- [x] Winsock hooking and local proxy redirection
- [x] Internal ENet hook to capture plaintext before encryption
- [x] Packet framing + protocol/message-type decoding in the analyzer
- [ ] **Decryption key extraction** — current blocker. Reading traffic straight off the
      wire still yields ciphertext; the internal-hook path is the workaround while this
      is unsolved.
- [ ] End-to-end plaintext capture without relying on the internal hook

## Building

Visual Studio (MSVC, x64). Open each project's `.vcxproj` (or the `.slnx`) and build.

- `MyProject_DLL` builds the injectable DLL.
- `MyProject_GUI` builds the launcher/analyzer.

The ENet hook depends on [MinHook] — add it to the DLL project's include/link path.

## Disclaimer

Built as a personal reverse-engineering / network-protocol learning project, for use
against my own client on my own machine. Not affiliated with or endorsed by the game's
developers. Provided as-is, for educational purposes.

[MinHook]: https://github.com/TsudaKageyu/minhook
