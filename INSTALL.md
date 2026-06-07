# PROXCLIP Installation Guide

**Version 1.0.5 — Sysop Network**

PROXCLIP is developed and maintained by Mark Laudenbach at Sysop Network.

---

## Overview

PROXCLIP is a module for The Major BBS v10 that restores real caller IP addresses when your BBS sits behind a reverse proxy. When a proxy such as BBSFirewall forwards incoming telnet connections, the BBS normally sees the proxy's IP for every user. PROXCLIP reads the PROXY Protocol v1 header that the proxy inserts and patches the real caller IP into the BBS channel record before login begins.

PROXCLIP works with any proxy server that supports PROXY Protocol v1, including:

- **BBSFirewall** (Sysop Network)
- **HAProxy**
- **nginx** (with `proxy_protocol on`)
- **Traefik**
- **AWS Network Load Balancer**
- Any other PROXY Protocol v1-compliant proxy

---

## Prerequisites

Before installing PROXCLIP, confirm the following:

- **The Major BBS v10** is installed and running
- **GALTNTD** (Telnet Server) is installed and listed in `wgserv.cfg`
- A PROXY Protocol v1-capable proxy is installed and sitting in front of port 23
- You have access to the BBS installation directory on the server
- You have access to edit `wgserv.cfg`

---

## Package Contents

The release package contains two files:

| File | Description |
|------|-------------|
| `PROXCLIP.DLL` | The PROXCLIP module |
| `PROXCLIP.MDF` | Module Definition File required by The Major BBS |

---

## Step 1 — Enable PROXY Protocol on Your Proxy Server

PROXCLIP expects your proxy to send a PROXY Protocol v1 header on every incoming connection. How you enable this depends on your proxy software.

**BBSFirewall:**

In your BBSFirewall `.env` file, set:

```
PROXY_PROTOCOL_ENABLED=true
```

Restart BBSFirewall after making this change.

**HAProxy:**

In your HAProxy frontend, add `send-proxy` to the server line:

```
server bbs 127.0.0.1:23 send-proxy
```

**nginx:**

In your stream block, add `proxy_protocol on`:

```
stream {
    server {
        listen 23;
        proxy_pass 127.0.0.1:23;
        proxy_protocol on;
    }
}
```

> **Note:** Once PROXY Protocol is enabled, your proxy will prepend a header line to every forwarded connection. If PROXCLIP is not yet installed on the BBS, users will see the raw header text appear on their screen at login. Install PROXCLIP promptly after enabling this setting.

---

## Step 2 — Upload Files to the BBS Server

Copy both files from the release package into your BBS installation directory — the same folder that contains `wgserver.exe`:

```
PROXCLIP.DLL  →  C:\BBSV10\PROXCLIP.DLL
PROXCLIP.MDF  →  C:\BBSV10\PROXCLIP.MDF
```

*(Adjust the path to match your actual BBS installation directory.)*

---

## Step 3 — Edit wgserv.cfg

Open `wgserv.cfg` in a text editor. Locate the GALTNTD entry — it will look similar to this:

```
DLL=GALTNTD
APP=GALTNTD Telnet Server
```

Add the two PROXCLIP lines **immediately after** the GALTNTD block:

```
DLL=GALTNTD
APP=GALTNTD Telnet Server

DLL=PROXCLIP
APP=PROXCLIP Proxy Client IP by Sysop Network
```

> **Load order is critical.** PROXCLIP must appear after GALTNTD in `wgserv.cfg`. PROXCLIP hooks into a function pointer that GALTNTD sets up at startup. If PROXCLIP loads first, that pointer will not exist yet and the module will disable itself with a fatal message in the Audit Trail.

Save `wgserv.cfg`.

---

## Step 4 — Restrict Port 23 to the Proxy Server (Required)

PROXCLIP trusts the PROXY Protocol header from any connection that presents one. If port 23 is reachable directly from the internet — bypassing the proxy — a malicious caller could send a forged PROXY header and impersonate any IP address, including ones not on a ban list.

**You must add a Windows Firewall rule on the BBS server** so that only your proxy server can reach port 23. Configure an inbound allow rule on port 23 restricted to your proxy server's IP address, and a block rule for everything else. Add one allow rule per proxy server if you run more than one.

> Trusted source validation built into the module is planned for PROXCLIP v1.10. Until then, this firewall rule is the required mitigation.

---

## Step 5 — Restart The Major BBS

Perform a full shutdown and restart of The Major BBS so the new module is loaded.

---

## Step 6 — Verify Installation

After the BBS restarts, check the Audit Trail for the PROXCLIP initialization messages:

```
PROXCLIP v1.0.5    initializing
PROXCLIP v1.0.5    recv hook installed in GALTNTD -- no-sleep mode
PROXCLIP v1.0.5    hdlcon hook installed -- real IP detection active
```

If you see these three lines, PROXCLIP loaded and both hooks installed successfully. The `recv hook installed` line confirms the IAT patch succeeded and PROXCLIP is operating in no-sleep mode.

Once a user connects through your proxy, you should see their real IP in the Audit Trail instead of the proxy's IP:

```
PROXCLIP              Chan 03    chan 03: real IP 203.0.113.42
USER LOGON VIA TELNET Chan 03    User-ID: Caller1, from 203.0.113.42
```

---

## Troubleshooting

### "FATAL: hdlcon is NULL — PROXCLIP must load AFTER GALTNTD"

PROXCLIP is listed before GALTNTD in `wgserv.cfg`. Move the PROXCLIP `DLL=` and `APP=` lines to after the GALTNTD entries and restart.

### "FATAL: GALTCPIP.DLL not loaded"

GALTCPIP is not loaded or has not initialised before PROXCLIP. Verify GALTCPIP is present in `wgserv.cfg` and that the BBS is starting without errors before the PROXCLIP line is reached.

### "FATAL: _tcpipinf symbol not found"

The installed version of `GALTCPIP.DLL` does not export the expected symbol. This indicates a version mismatch. Contact Sysop Network for assistance.

### Users connecting through the proxy still show the proxy IP

- Confirm PROXY Protocol is enabled on your proxy and that the proxy was restarted.
- Confirm the two Audit Trail init messages appear when the BBS starts.
- Check that users are actually connecting through the proxy and not directly to port 23.

### BBS fails to start after adding PROXCLIP

- Remove the PROXCLIP `DLL=` and `APP=` lines from `wgserv.cfg` temporarily to restore normal operation.
- Verify both `PROXCLIP.DLL` and `PROXCLIP.MDF` are present in the BBS installation directory.
- Check the Audit Trail for any error message from PROXCLIP on the previous startup attempt.

---

## Uninstalling PROXCLIP

1. Remove the `DLL=PROXCLIP` and `APP=PROXCLIP ...` lines from `wgserv.cfg`.
2. Restart The Major BBS.
3. Optionally delete `PROXCLIP.DLL` and `PROXCLIP.MDF` from the BBS installation directory.

If you also want to stop your proxy from sending PROXY headers, disable the setting in your proxy configuration and restart it.

---

## Support

For issues or questions, visit the PROXCLIP GitHub repository or contact Sysop Network.

PROXCLIP is developed and maintained by Mark Laudenbach at Sysop Network.  
Copyright (c) 2026 Sysop Network. Released under the MIT License.
