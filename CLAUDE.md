# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

PROXCLIP is a Win32 DLL module for **The Major BBS v10 (Worldgroup)**. It restores real caller IP addresses when the BBS runs behind a PROXY Protocol v1-capable reverse proxy (e.g. BBSFirewall, HAProxy, nginx). It is a single-file C project.

## Build

Open `PROXCLIP.vcxproj` in **Visual Studio 2022** and build. There is no command-line build script.

- **Release** output: `..\..\Releases\proxclip\v1.0.7\PROXCLIP.DLL` (and `.MDF` copied by post-build event)
- **Debug** output: `..\..\Releases\proxclip\v1.00-debug\PROXCLIP.DLL`

The MBBS SDK must exist at `..\..\CLAUDE RESOURCES\MBBS 10 SDK\` relative to the project directory, with headers under `inc\` and `inc\msg\v10\` and import libs under `lib\importlibs\` and `lib\v10\`.

### Critical compiler settings (must not be changed)

| Setting | Value | Reason |
|---------|-------|--------|
| Target | Win32 DLL | `WGSERVER.EXE` is a 32-bit process |
| Runtime | `/MT` Release, `/MTd` Debug | Server lacks `VCRUNTIME140.dll` |
| Struct alignment | `/Zp8` | Matches MBBS SDK header layout |
| Char type | `/J` | MBBS `unsigned char` convention |
| SDL checks | Off | MBBS APIs use deprecated C patterns |
| `winsock2.h` | Must be included before any SDK header | SDK pulls in `windows.h` → `winsock.h`; `winsock2.h` first sets `_WINSOCK2API_` to block the conflict |

### Preprocessor defines required

`WIN32;GCWINNT;GCMVC;BBSVER=1000;USE_DEF_FILE;_CRT_SECURE_NO_WARNINGS;_CRT_SECURE_NO_DEPRECATE;_CRT_NONSTDC_NO_DEPRECATE;__BUILDV10MODULE`

### Export alias

`PROXCLIP_EXP.DEF` exports `_init__proxclip=init__proxclip` — MBBS calls `GetProcAddress(hDLL, "_init__proxclip")` (leading underscore), but MSVC generates the cdecl symbol without it.

## Architecture

Everything lives in `PROXCLIP.C` (one translation unit). The module installs two hooks at `init__proxclip` time and removes them in `proxclip_fin`.

### Hook 1 — `hdlcon` function pointer

`WGSERVER.EXE` exports a global `hdlcon` pointer. GALTNTD's `incall()` calls it for every new telnet connection, with `usrnum` and `tcpipinf[usrnum]` valid on entry. PROXCLIP chains:

```
hcsave = hdlcon → hdlcon = proxclip_hdlcon
```

`proxclip_hdlcon` stores the socket in `pending_skt[usrnum]`, then immediately calls `hcsave()`. No sleep or polling.

**Load order constraint:** PROXCLIP must init after GALTNTD so `hdlcon` is non-NULL. The MDF declares `INTERNAL` + `UNCONDITIONAL`, which causes MBBS to load PROXCLIP automatically after the standard telnet stack — satisfying the dependency without a `wgserv.cfg` entry.

### Hook 2 — `recv()` IAT patch in GALTNTD.DLL

`patch_iat_recv()` walks GALTNTD.DLL's PE import directory, finds the `recv` slot (matched by name or ordinal against the known `WS2_32.dll!recv` address), and replaces it with `prx_recv_hook` via `VirtualProtect`. Falls back to GALTCPIP.DLL if GALTNTD doesn't import `recv` directly.

`prx_recv_hook` fires on every `recv()` call from GALTNTD. For a pending socket's first non-peek call it runs `prx_consume_header()`, which peeks at the buffer, skips any leading `\r`/`\n` (MegaMUD quirk), checks for `"PROXY "`, parses the header, and writes `(*pp_tcpipinf)[unum].inaddr = real_ip`. Then it calls through to `real_recv` (saved original). PROXCLIP's own `recv()` calls bypass the patched IAT via PROXCLIP's unpatched import — no recursion.

### Runtime symbol resolution

`tcpipinf` is resolved at runtime via `GetProcAddress(hGaltcpip, "_tcpipinf")` (ordinal 43, cdecl underscore prefix) rather than linking `GALTCPIP_LIB.LIB`, which causes ordinal-mismatch load failures on some servers.

### MBBS module struct

```c
struct module PROXCLIP = {
    /* huprou */ proxclip_hup,   // clears pending_skt on disconnect
    /* finrou */ proxclip_fin    // restores IAT and hdlcon on shutdown
};
```

All other slots are NULL — PROXCLIP has no user-facing state, no logon supplement, no menu.

## Deployment

Copy `PROXCLIP.DLL` and `PROXCLIP.MDF` to the BBS installation directory (typically `C:\BBSV10`). MBBS loads it automatically on restart. No `wgserv.cfg` entry required.

**Security requirement:** Restrict inbound port 23 to the proxy server's IP using Windows Firewall. Without this, any direct caller can forge a PROXY header and spoof their IP.
