<div align="center">

```
  ██████╗ ██████╗  ██████╗ ██╗  ██╗ ██████╗██╗     ██╗██████╗ 
  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝██║     ██║██╔══██╗
  ██████╔╝██████╔╝██║   ██║ ╚███╔╝ ██║     ██║     ██║██████╔╝
  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ██║     ██║     ██║██╔═══╝ 
  ██║     ██║  ██╗╚██████╔╝██╔╝ ██╗╚██████╗███████╗██║██║     
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝╚═╝     
```

**Real caller IP restoration for The Major BBS v10 when running behind a reverse proxy.**

By **[Mark Laudenbach](https://github.com/laudenbachm)** at **[Sysop Network](https://github.com/SysopNetwork)** — https://github.com/laudenbachm/PROXCLIP

[![License](https://img.shields.io/badge/license-MIT-blue?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%28Win32%29-0078D6?logo=windows&logoColor=white)]()
[![BBS](https://img.shields.io/badge/The%20Major%20BBS-v10-brightgreen)]()
[![PROXY Protocol](https://img.shields.io/badge/PROXY%20Protocol-v1-lightgrey)]()

</div>

---

## ✨ What It Does

| | Feature | Description |
|---|---|---|
| 🌐 | **Real IP Restoration** | Reads the PROXY Protocol v1 header and patches the real caller IP into the BBS channel record before login begins |
| 🔒 | **Transparent** | The BBS sees and logs the real IP exactly as it would for a direct connection — no changes to login flow |
| 🔌 | **Hook-Based** | Hooks `hdlcon` in `wgserver.exe` and `recv()` in GALTNTD.DLL — no GALTNTD source changes required |
| 🎮 | **MegaMUD Compatible** | Handles the leading `\r` byte some clients send on connect before any telnet negotiation |
| 📡 | **Proxy Agnostic** | Works with any PROXY Protocol v1-capable proxy: BBSFirewall, HAProxy, nginx, Traefik, AWS NLB, and others |
| 🚫 | **Pass-Through Safe** | Connections without a PROXY header are untouched — direct connections continue to work normally |

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| BBS software | The Major BBS v10 (Worldgroup) |
| Proxy software | Any PROXY Protocol v1-capable reverse proxy |
| Load order | PROXCLIP must appear **after** GALTNTD in `wgserv.cfg` |
| Runtime | No external DLL dependencies — statically linked (`/MT`) |

---

## 🚀 Quick Install

1. Copy `PROXCLIP.DLL` and `PROXCLIP.MDF` from the [`DIST/`](DIST/) folder to your BBS installation directory.
2. Add the following to `wgserv.cfg` **after** the GALTNTD entries:
   ```
   DLL=PROXCLIP
   APP=PROXCLIP Proxy Client IP by Sysop Network
   ```
3. Enable PROXY Protocol v1 on your proxy server.
4. Restart the BBS.

See [INSTALL.md](INSTALL.md) for the full step-by-step guide, including proxy-specific configuration examples and troubleshooting.

---

## ⚙️ wgserv.cfg Configuration

PROXCLIP must be listed **after** GALTNTD in `wgserv.cfg`. Locate the GALTNTD block and insert the two lines immediately after it:

```
DLL=GALTNTD
APP=GALTNTD Telnet Server

DLL=PROXCLIP
APP=PROXCLIP Proxy Client IP by Sysop Network
```

> **Load order is critical.** PROXCLIP hooks a function pointer that GALTNTD sets up at startup. If PROXCLIP loads first, that pointer will not exist yet and the module will disable itself with a fatal message in the Audit Trail.

---

## 🔒 Security

PROXCLIP trusts the PROXY Protocol header from any connection that presents one. If port 23 on your BBS server is reachable directly from the internet — bypassing the proxy — a malicious caller could forge a PROXY header and impersonate any IP address, including ones not on a ban list.

**Use Windows Firewall on the BBS server** to restrict inbound port 23 access to the proxy server's IP address only. This ensures the PROXY header can only arrive from a trusted source.

> Trusted source validation built into the module is planned for PROXCLIP v1.10.

---

## 🖥️ Compatible Proxy Servers

PROXCLIP implements the [PROXY Protocol v1](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) open standard and works with any proxy that supports it:

- **[BBSFirewall](https://github.com/SysopNetwork/BBSFirewall)** *(recommended — purpose-built for BBS environments)*
- HAProxy
- nginx (stream proxy with `proxy_protocol on`)
- Traefik
- AWS Network Load Balancer
- Any other PROXY Protocol v1-compliant proxy

BBSFirewall is the recommended companion for The Major BBS. It handles BBS-specific protocols, country blocking, rate limiting, and connection management alongside PROXY Protocol support.

---

## 📡 How It Works

PROXCLIP installs two hooks at startup.

**hdlcon hook:** PROXCLIP replaces the `hdlcon` global function pointer in `wgserver.exe`. When GALTNTD accepts a new telnet connection it calls `hdlcon` — which now calls PROXCLIP's handler first. PROXCLIP records the new socket as pending and immediately hands off to GALTNTD's normal handler with no delay.

**recv hook:** PROXCLIP also patches the `recv()` entry in GALTNTD.DLL's import address table, routing all of GALTNTD's socket reads through a thin wrapper. When GALTNTD makes its first read on a pending socket, the wrapper fires before any data reaches GALTNTD. It peeks at the socket buffer, and if a PROXY Protocol v1 header is present, consumes exactly those bytes, writes the real caller IP into `tcpipinf[usrnum].inaddr`, and returns the remaining data to GALTNTD — as if the header never existed. The hook fires at exactly the right moment regardless of network latency.

Connections that do not carry a PROXY header are passed through untouched with zero modification to the socket stream.

For a complete technical breakdown, see [TECHNICAL.md](TECHNICAL.md).

---

## 📋 Audit Trail Output

Successful IP patch:

```
PROXCLIP    Chan 01    chan 01: real IP 203.0.113.42
```

Error conditions are also logged and the connection is passed through:

```
PROXCLIP    chan 02: incomplete PROXY header (49 bytes), passing through
PROXCLIP    chan 04: bad PROXY header (fields=2), passing through
```

---

## 📁 Files

| File | Description |
|------|-------------|
| `PROXCLIP.DLL` | The PROXCLIP module |
| `PROXCLIP.MDF` | Module Definition File required by The Major BBS |
| `PROXCLIP.C` | Module source |
| `PROXCLIP.H` | Header |
| `PROXCLIP.rc` | Version and copyright resource |
| `PROXCLIP_EXP.DEF` | Linker export aliases for MSVC |
| `PROXCLIP.vcxproj` | Visual Studio 2022 project file |

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](INSTALL.md) | Step-by-step installation guide with proxy-specific configuration examples and troubleshooting |
| [TECHNICAL.md](TECHNICAL.md) | Detailed technical reference — hook mechanism, execution flow, runtime symbol resolution, build configuration |

---

## 🔖 Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.0.6 | 2026-06-07 | Fix audit trail channel number off-by-one — body now matches the Chan display in the MBBS audit header; add DLL version and copyright resource; update MDF fields |
| 1.0.5 | 2026-06-01 | Replace sleep-based wait with recv() IAT hook in GALTNTD.DLL — no blocking, timing-independent |
| 1.0.3 | 2026-06-01 | Fix channel numbers in audit trail — now displayed as two-digit hex (01–ff) to match MBBS convention |
| 1.0.2 | 2026-06-01 | Fix connection failures introduced in v1.0.1; Sleep(1) x 25ms replaces broken polling path |
| 1.0.1 | 2026-06-01 | Removed goto statements; attempted non-blocking poll (reverted — not viable in hdlcon context) |
| 1.00 | 2026-05-27 | Initial release |

---

## 🏆 Credits

PROXCLIP is developed and maintained by [Mark Laudenbach](https://github.com/laudenbachm) at [Sysop Network](https://github.com/SysopNetwork).

---

## 📄 License

MIT — Copyright (c) 2026 Sysop Network
