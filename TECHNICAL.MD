# PROXCLIP — Technical Reference

**How It Works: A detailed explanation for The Major BBS developers**

PROXCLIP is developed and maintained by Mark Laudenbach at Sysop Network.  
Copyright (c) 2026 Sysop Network. All Rights Reserved.

---

## Problem Statement

The Major BBS v10 records the caller's IP address at the moment GALTNTD's `incall()` function processes a new TCP connection. This happens inside `GALTCPIP.DLL`'s `dispatchCall()` function, which copies `claddr.sin_addr` (the address returned by `accept()`) directly into `tcpipinf[slot].inaddr`.

When a reverse proxy sits in front of port 23, `accept()` returns the proxy's IP for every connection. The real caller IP is not visible at the socket layer — it is only known to the proxy. The proxy communicates it out-of-band using the PROXY Protocol.

PROXCLIP bridges the gap by reading the PROXY Protocol header from the raw socket before the BBS login machinery sees any data, then writing the real IP into the channel's `tcpipinf` slot.

---

## PROXY Protocol v1

A PROXY Protocol v1-capable proxy prepends the following ASCII line to the TCP byte stream immediately after the three-way handshake, before any telnet data:

```
PROXY TCP4 <client-ip> <proxy-ip> <client-port> <proxy-port>\r\n
```

Example:

```
PROXY TCP4 203.0.113.42 192.0.2.1 54321 23\r\n
```

- **client-ip**: the real caller's IP address — the value PROXCLIP writes into `tcpipinf`.
- **proxy-ip**: BBSFirewall's outbound IP (the BBS server sees this from `accept()`).
- **client-port / proxy-port**: source and destination ports (recorded but not used by PROXCLIP).

The header is always terminated with `\r\n` and is at most 107 bytes plus the two-byte terminator (108 bytes total). PROXCLIP uses a 109-byte buffer to hold the header plus a NUL terminator.

### Client quirk: leading CR

Some clients (notably MegaMUD) send a bare `\r` (0x0D) immediately on TCP connect before any telnet negotiation. BBSFirewall receives this byte and forwards it to the BBS before transmitting the PROXY header, so the socket may present:

```
0D 50 52 4F 58 59 20 54 43 50 34 20 ...
\r  P  R  O  X  Y     T  C  P  4   ...
```

PROXCLIP handles this by scanning past any leading `\r`/`\n` bytes before checking for the `PROXY ` signature.

---

## Hook Mechanism

PROXCLIP installs two hooks at startup: one at the connection level (`hdlcon`) and one at the socket read level (IAT patch on `recv`).

### Hook 1 — The `hdlcon` global function pointer

`WGSERVER.EXE` exports a global function pointer `hdlcon` (type `VOID (*)(VOID)`). GALTNTD's `incall()` calls this pointer for every new accepted telnet connection. `usrnum` and `tcpipinf[usrnum]` are valid on entry.

PROXCLIP uses a standard hook chain pattern:

```
At init time:
    hcsave = hdlcon;           /* save GALTNTD's handler */
    hdlcon = proxclip_hdlcon;  /* insert ours */

At shutdown (proxclip_fin):
    hdlcon = hcsave;           /* restore original */
```

`proxclip_hdlcon` records the new socket as pending in `pending_skt[usrnum]`, then immediately calls `hcsave()` — GALTNTD's original handler. There is no sleep, no polling, no wait of any kind.

### Hook 2 — recv() IAT patch in GALTNTD.DLL

GALTNTD.DLL imports `recv` from `WS2_32.dll` by ordinal (ordinal 16). PROXCLIP walks GALTNTD.DLL's PE import address table at init time and replaces that one slot with a pointer to `prx_recv_hook`:

```
At init time:
    find recv slot in GALTNTD.DLL IAT  (ordinal match by address comparison)
    VirtualProtect → PAGE_READWRITE
    *slot = prx_recv_hook              /* our wrapper */
    VirtualProtect → restore

At shutdown (proxclip_fin):
    VirtualProtect → PAGE_READWRITE
    *slot = real_recv                  /* original ws2_32!recv */
    VirtualProtect → restore
```

`prx_recv_hook` is called whenever GALTNTD calls `recv()` on any socket. For sockets in the pending table it runs `prx_consume_header()` before returning data. For all other sockets (and for `MSG_PEEK` calls) it passes through to the real `recv` immediately.

### Why the IAT approach works

GALTCPIP.DLL drives the socket event loop using `WSAAsyncSelect`. When data arrives on a socket, Windows fires a `WM_SOCKET_NOTIFY` message to GALTCPIP's hidden window. GALTCPIP's window proc does a 1-byte `MSG_PEEK` check to confirm data is present, then calls `hdlsock()`, which dispatches to GALTNTD's registered socket event handler. GALTNTD's handler calls `recv()` to read the raw bytes — at which point our hook fires.

This is the earliest possible moment to intercept the data: GALTCPIP has confirmed data is in the socket buffer, and GALTNTD is about to read it. The PROXY header is guaranteed to be present at this point. There is no race, no timing dependency.

PROXCLIP.DLL's own `recv()` calls (used inside `prx_consume_header`) go through PROXCLIP's own unpatched IAT, not GALTNTD's patched one — so there is no recursion.

### Load order requirement

PROXCLIP reads `hdlcon` at init time, so it must initialise after GALTNTD. The MDF declares the module `INTERNAL` and `UNCONDITIONAL`, which causes MBBS to load it automatically with no `wgserv.cfg` entry required. MBBS loads internal modules after the standard telnet stack, satisfying the order dependency automatically.

If `hdlcon` is NULL when `init__proxclip` runs (e.g. GALTNTD is not installed), the module logs a fatal message and returns without hooking — existing connections continue to work, PROXCLIP is simply inactive.

---

## Runtime Symbol Resolution

PROXCLIP needs `tcpipinf`, the array of per-channel TCP state maintained by `GALTCPIP.DLL`. The clean approach would be to link against `GALTCPIP_LIB.LIB`, but that causes DLL load failure on some servers due to an ordinal mismatch between the import library and the installed DLL.

Instead, PROXCLIP resolves the symbol at runtime:

```c
HMODULE hGaltcpip = GetModuleHandleA("GALTCPIP.DLL");
pp_tcpipinf = (struct tcpipinf **)GetProcAddress(hGaltcpip, "_tcpipinf");
```

`GALTCPIP.DLL` exports `_tcpipinf` (with leading underscore, MSVC cdecl convention) at ordinal 43. `GetModuleHandle` is used rather than `LoadLibrary` because GALTCPIP is already loaded by the time PROXCLIP initialises — this avoids incrementing the reference count.

---

## Execution Flow Per Connection

```
TCP accept() in GALTCPIP.DLL
    → tcpipinf[slot].inaddr = claddr.sin_addr   (proxy IP written here)
    → hdlcon() called
        → proxclip_hdlcon()
            1. Get socket fd from tcpipinf[usrnum].socket
            2. pending_skt[usrnum] = socket   (mark as pending)
            3. hcsave()                       (GALTNTD's original handler)
                → GALTNTD registers socket event handler, begins login setup

    ... time passes, BBSFirewall sends PROXY header, data arrives ...

    → WM_SOCKET_NOTIFY (FD_READ) fires in GALTCPIP's window proc
        → 1-byte MSG_PEEK confirms data present
        → hdlsock() dispatches to GALTNTD's socket event handler
            → GALTNTD's handler calls recv(socket, buf, len, 0)
                → prx_recv_hook() fires  [our IAT hook]
                    1. Check: usrnum valid && pending_skt[usrnum] == socket
                    2. Clear pending_skt[usrnum] = INVALID_SOCKET
                    3. prx_consume_header(socket, usrnum)
                        a. recv(..., MSG_PEEK) — inspect without consuming
                        b. Skip leading \r/\n bytes
                        c. If not "PROXY " → return 0 (not a PROXY header)
                        d. Find \r\n end-of-header position
                        e. recv(..., 0) — consume exactly the header bytes
                        f. sscanf to extract src-ip
                        g. inet_addr to parse
                        h. tcpipinf[usrnum].inaddr = real_ip   ← THE PATCH
                        i. Log "chan NN: real IP x.x.x.x"
                    4. recv(socket, buf, len, 0)  [real ws2_32!recv]
                        → returns post-header data to GALTNTD
                → GALTNTD processes telnet data normally
```

### Why MSG_PEEK in the hook?

`recv(..., MSG_PEEK)` reads the socket buffer without consuming bytes. PROXCLIP uses it to look at the incoming data and decide whether a PROXY header is present before committing to consume it. If the data is not a PROXY header (a direct connection, a mid-session recv, etc.), the bytes are left in the buffer for GALTNTD to read normally.

Only once a PROXY header is confirmed does PROXCLIP perform a consuming `recv` — and only for exactly the byte count of the header line. Everything after the `\r\n` remains in the socket buffer and is returned to GALTNTD by the tail call in `prx_recv_hook`.

### Why the recv hook fires at exactly the right moment

GALTCPIP's `FD_READ` handler does a 1-byte `MSG_PEEK` before calling `hdlsock`. That peek confirms there is data in the socket buffer. By the time `hdlsock` dispatches to GALTNTD's handler, and GALTNTD calls `recv()`, the PROXY header is guaranteed to be sitting in the buffer. No timing assumptions required.

---

## Export Naming

The Major BBS module loader calls `GetProcAddress(hDLL, "_init__proxclip")` — with a leading underscore. MSVC generates `init__proxclip` internally (cdecl, no decoration for `void __cdecl` in a plain C file). The DEF file alias bridges the gap:

```
EXPORTS
    _init__proxclip=init__proxclip    @1
```

This instructs the linker to export the symbol under the name `_init__proxclip` (what MBBS looks for) while the internal C symbol remains `init__proxclip` (no double underscore).

---

## Build Configuration

| Setting | Value | Reason |
|---------|-------|--------|
| Target | Win32 DLL | WGSERVER.EXE is a 32-bit process |
| Runtime | `/MT` (static) | Server lacks `VCRUNTIME140.dll` |
| Struct alignment | `/Zp8` | Matches MBBS SDK header expectations |
| Char type | `/J` (unsigned char) | MBBS convention |
| Include paths | `MBBS SDK\inc`, `MBBS SDK\inc\msg\v10` | MBBS v10 headers |
| Libraries | `wgserver_lib.lib`, `galgsbl_lib.lib`, `ws2_32.lib` | MBBS exports + Winsock |

---

## Files

| File | Purpose |
|------|---------|
| `PROXCLIP.C` | Module source — hook logic, IP patching |
| `PROXCLIP.H` | Header (minimal; reserved for future defines) |
| `PROXCLIP.rc` | Version and copyright resource |
| `PROXCLIP_EXP.DEF` | Linker export aliases for MSVC |
| `PROXCLIP.vcxproj` | Visual Studio 2022 project file |

---

## Known Limitation — IP Spoofing (v1.0.6)

PROXCLIP v1.0.6 trusts the PROXY Protocol header from any connection that presents one. It does not validate that the connection originated from a known proxy server. A caller who can reach port 23 directly can send a crafted `PROXY TCP4 x.x.x.x ...` header and impersonate any IP address.

**Required mitigation for v1.0.6:** Restrict inbound port 23 access on the BBS server to the proxy server's IP using Windows Firewall. This ensures the PROXY header can only arrive from a trusted source.

Trusted source validation built into the module — checking the raw socket IP against a configured list of trusted proxy addresses before processing any PROXY header — is planned for v1.1.0.

---

## Planned for v1.1.0

- **Trusted source validation**: Configurable list of trusted proxy IPs stored in the MBBS CNF system. PROXY headers from any other source will be ignored regardless of content.

---

## Potential Future Enhancements

- **PROXY Protocol v2** (binary format): BBSFirewall currently uses v1 (ASCII). If v2 support is added to BBSFirewall, PROXCLIP would need a second parsing path checking for the 12-byte binary signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`.

---

## About

Released under the [MIT License](LICENSE).

PROXCLIP is developed and maintained by [Mark Laudenbach](https://github.com/laudenbachm) at [Sysop Network](https://github.com/SysopNetwork).