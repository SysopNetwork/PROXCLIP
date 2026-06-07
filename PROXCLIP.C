/***************************************************************************
 *                                                                         *
 *   PROXCLIP.C  --  Proxy Client IP                                       *
 *                                                                         *
 *   A companion module for BBSFirewall on The Major BBS v10               *
 *                                                                         *
 *   Hooks the hdlcon vector so every incoming telnet connection on port   *
 *   23 passes through here first.  If BBSFirewall sent a PROXY Protocol   *
 *   v1 header, we consume it and patch tcpipinf[usrnum].inaddr with the   *
 *   real caller IP before normal login begins.  Direct connections (no    *
 *   header) pass through untouched.                                       *
 *                                                                         *
 *   LOAD ORDER: must appear AFTER GALTNTD in wgserv.cfg or the hdlcon    *
 *   pointer will be NULL at init and nothing will work.                   *
 *                                                                         *
 *   v1.1.0 -- No-sleep approach: IAT-patch recv() in GALTNTD.DLL so      *
 *   the PROXY header is consumed the instant GALTNTD reads it from the    *
 *   socket, before any telnet processing occurs.  proxclip_hdlcon now     *
 *   records the socket as "pending" and calls hcsave() immediately.       *
 *   If GALTNTD.DLL does not import recv, GALTCPIP.DLL is tried instead.   *
 *                                                                         *
 *   PROXCLIP is developed and maintained by Mark Laudenbach               *
 *   at Sysop Network.                                                     *
 *                                                                         *
 *   Copyright (c) 2026 Sysop Network.  All Rights Reserved.              *
 *                                                                         *
 ***************************************************************************/

/*
 * winsock2.h MUST come before any SDK header.  The SDK's tcpip.h pulls
 * windows.h which drags in the old winsock.h -- including winsock2.h first
 * sets _WINSOCK2API_ which blocks the double-include.
 */
#include <winsock2.h>
#include <windows.h>

#include "gcomm.h"
#include "majorbbs.h"
#include "tcpip.h"
#include "PROXCLIP.H"

#include <stdio.h>
#include <string.h>

#define PROXCLIP_VERSION "v1.0.6"

/*
 * Pending socket table, indexed by usrnum.
 * INVALID_SOCKET means no PROXY header processing is pending for that slot.
 * Set in proxclip_hdlcon, cleared in prx_recv_hook or proxclip_hup.
 */
static SOCKET pending_skt[MAXNTERM];

/*
 * IAT patch state.
 * We patch recv() in either GALTNTD.DLL or GALTCPIP.DLL.
 * patched_iat_entry points into the module's IAT so we can restore it.
 * real_recv is the original function address saved from that slot.
 */
typedef int (WINAPI *recv_fn_t)(SOCKET, char *, int, int);
static recv_fn_t  real_recv        = NULL;
static recv_fn_t *patched_iat_entry = NULL;

/*
 * tcpipinf is resolved at runtime to avoid linking GALTCPIP_LIB.LIB,
 * which causes DLL load failure on this server (ordinal mismatch).
 */
static struct tcpipinf **pp_tcpipinf = NULL;

/* saved hdlcon pointer -- we chain to this after our processing */
static VOID (*hcsave)(VOID) = NULL;

static VOID     proxclip_hdlcon(VOID);
static VOID     proxclip_hup(VOID);
static VOID     proxclip_fin(VOID);
static INT      prx_consume_header(SOCKET skt, INT unum);
static int WINAPI prx_recv_hook(SOCKET s, char *buf, int len, int flags);
static recv_fn_t *find_iat_recv(HMODULE hMod);
static recv_fn_t  patch_iat_recv(HMODULE hMod, recv_fn_t new_fn);

struct module PROXCLIP = {
    "",             /* descrp:  filled from MDF at init                  */
    NULL,           /* lonrou:  no logon supplement                      */
    NULL,           /* sttrou:  users never enter this module's state    */
    NULL,           /* stsrou:  no status-input handler                  */
    NULL,           /* injrou:  no injoth handler                        */
    NULL,           /* lofrou:  no logoff supplement                     */
    proxclip_hup,   /* huprou:  clear pending on disconnect              */
    NULL,           /* mcurou:  no midnight cleanup                      */
    NULL,           /* dlarou:  no delete-account handler                */
    proxclip_fin    /* finrou:  unhook on shutdown                       */
};

void EXPORT
init__proxclip(VOID)
{
    HMODULE hGaltcpip, hGaltntd;
    INT i;

    shocst("PROXCLIP " PROXCLIP_VERSION, "initializing");

    stzcpy(PROXCLIP.descrp, gmdnam("PROXCLIP.MDF"), MNMSIZ);
    register_module(&PROXCLIP);

    /* Initialize pending table */
    for (i = 0; i < MAXNTERM; i++)
        pending_skt[i] = INVALID_SOCKET;

    /* Grab tcpipinf from GALTCPIP at runtime. */
    hGaltcpip = GetModuleHandleA("GALTCPIP.DLL");
    if (hGaltcpip == NULL) {
        shocst("PROXCLIP", "FATAL: GALTCPIP.DLL not loaded -- disabled");
        return;
    }
    pp_tcpipinf = (struct tcpipinf **)GetProcAddress(hGaltcpip, "_tcpipinf");
    if (pp_tcpipinf == NULL) {
        shocst("PROXCLIP", "FATAL: _tcpipinf symbol not found -- disabled");
        return;
    }

    /* hdlcon must already be set by GALTNTD. */
    if (hdlcon == NULL) {
        shocst("PROXCLIP", "FATAL: hdlcon is NULL -- PROXCLIP must load AFTER GALTNTD in wgserv.cfg");
        return;
    }
    hcsave = hdlcon;
    hdlcon = proxclip_hdlcon;

    /*
     * Patch recv() in GALTNTD.DLL first (preferred: that's where telnet
     * data is actually read).  Fall back to GALTCPIP.DLL if needed.
     *
     * real_recv is saved for fin-time restoration only; PROXCLIP.DLL's own
     * calls to recv() bypass the patched IATs via PROXCLIP's unpatched entry.
     */
    {
        INT patched_ntd = 0;
        hGaltntd = GetModuleHandleA("GALTNTD.DLL");
        if (hGaltntd != NULL) {
            real_recv = patch_iat_recv(hGaltntd, prx_recv_hook);
            if (real_recv != NULL) patched_ntd = 1;
        }
        if (real_recv == NULL)
            real_recv = patch_iat_recv(hGaltcpip, prx_recv_hook);

        if (real_recv != NULL) {
            shocst("PROXCLIP " PROXCLIP_VERSION,
                   spr("recv hook installed in %s -- no-sleep mode",
                       patched_ntd ? "GALTNTD" : "GALTCPIP"));
        } else {
            shocst("PROXCLIP", "WARNING: recv hook unavailable -- single-shot FIONREAD fallback");
        }
    }

    shocst("PROXCLIP " PROXCLIP_VERSION, "hdlcon hook installed -- real IP detection active");
}

/*
 * find_iat_recv
 *
 * Locates the IAT slot for recv() (from WS2_32.dll or wsock32.dll) in hMod.
 * Returns a pointer to the slot so the caller can read or write the address,
 * or NULL if not found.
 */
static recv_fn_t *
find_iat_recv(HMODULE hMod)
{
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    DWORD rva;

    if (hMod == NULL) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (rva == 0) return NULL;

    for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name != 0; imp++) {
        const char *dllname = (const char *)(base + imp->Name);
        IMAGE_THUNK_DATA *thunk, *orig;

        if (_stricmp(dllname, "WS2_32.dll") != 0 &&
            _stricmp(dllname, "wsock32.dll") != 0)
            continue;

        thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        {
            /* Precompute the real recv address for ordinal/stripped matching. */
            recv_fn_t ws2recv = (recv_fn_t)GetProcAddress(
                GetModuleHandleA("WS2_32.DLL"), "recv");

            if (imp->OriginalFirstThunk != 0) {
                /* Match by import name or, for ordinal entries, by address. */
                orig = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
                for (; orig->u1.Function != 0; orig++, thunk++) {
                    if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                        /* Imported by ordinal -- compare against known address. */
                        if (ws2recv != NULL &&
                            (recv_fn_t)(DWORD)thunk->u1.Function == ws2recv)
                            return (recv_fn_t *)&thunk->u1.Function;
                        continue;
                    }
                    {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                        if (_stricmp((const char *)ibn->Name, "recv") == 0)
                            return (recv_fn_t *)&thunk->u1.Function;
                    }
                }
            } else {
                /* OriginalFirstThunk stripped: match by current address. */
                if (ws2recv == NULL) continue;
                for (; thunk->u1.Function != 0; thunk++) {
                    if ((recv_fn_t)(DWORD)thunk->u1.Function == ws2recv)
                        return (recv_fn_t *)&thunk->u1.Function;
                }
            }
        }
    }
    return NULL;
}

/*
 * patch_iat_recv
 *
 * Replaces recv() in hMod's IAT with new_fn.  Returns the original address
 * (to use as the real recv and for restoration) or NULL on failure.
 */
static recv_fn_t
patch_iat_recv(HMODULE hMod, recv_fn_t new_fn)
{
    recv_fn_t *slot = find_iat_recv(hMod);
    recv_fn_t  old_fn;
    DWORD      old_prot;

    if (slot == NULL) return NULL;
    old_fn = *slot;
    VirtualProtect(slot, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
    *slot = new_fn;
    VirtualProtect(slot, sizeof(recv_fn_t), old_prot, &old_prot);
    if (patched_iat_entry == NULL)
        patched_iat_entry = slot;  /* remember for fin-time restore */
    return old_fn;
}

/*
 * prx_recv_hook
 *
 * Installed in place of recv() in GALTNTD.DLL (or GALTCPIP.DLL).
 *
 * When GALTNTD makes its first non-peek recv() call for a pending socket,
 * we intercept, strip the PROXY header, and patch the real IP.  Subsequent
 * recv() calls for the same socket pass through immediately.
 *
 * usrnum is valid here: hdlsock() calls curusr(usrnum) before invoking any
 * socket event handler, so it is set to the channel being processed.
 */
static int WINAPI
prx_recv_hook(SOCKET s, char *buf, int len, int flags)
{
    if (!(flags & MSG_PEEK) &&
        pp_tcpipinf != NULL &&
        usrnum >= 0 && usrnum < MAXNTERM &&
        pending_skt[usrnum] == s) {

        pending_skt[usrnum] = INVALID_SOCKET;   /* consume once only */
        prx_consume_header(s, usrnum);
    }

    /* Call through PROXCLIP.DLL's own unpatched IAT -- no recursion risk. */
    return recv(s, buf, len, flags);
}

/*
 * prx_consume_header
 *
 * Peeks at the socket buffer.  If a PROXY Protocol v1 header is present,
 * consumes those bytes (via recv) and patches tcpipinf[unum].inaddr with
 * the real caller IP.  If no valid header, socket is left untouched.
 */
static INT
prx_consume_header(SOCKET skt, INT unum)
{
    CHAR           hdr[128];    /* 107-byte max + \r\n + NUL fits easily */
    INT            n, hdr_start, hdr_end, i;
    CHAR           proto[16], src_ip[64], dst_ip[64];
    INT            src_port, dst_port, fields;
    struct in_addr real_ip;

    n = recv(skt, hdr, (INT)(sizeof(hdr) - 1), MSG_PEEK);
    if (n < 6)
        return 0;
    hdr[n] = '\0';

    /* Skip leading \r/\n (MegaMUD sends \r before the PROXY header). */
    hdr_start = 0;
    while (hdr_start < n && (hdr[hdr_start] == '\r' || hdr[hdr_start] == '\n'))
        hdr_start++;

    if ((n - hdr_start) < 6 || memcmp(hdr + hdr_start, "PROXY ", 6) != 0)
        return 0;

    /* Find \r\n terminator. */
    hdr_end = -1;
    for (i = 0; i < n - 1; i++) {
        if (hdr[i] == '\r' && hdr[i + 1] == '\n') {
            hdr_end = i + 2;
            break;
        }
    }
    if (hdr_end < 0) {
        shocst("PROXCLIP", spr("chan %02x: incomplete PROXY header (%d bytes), passing through", unum + 1, n));
        return 0;
    }

    /* Consume exactly the header from the socket. */
    recv(skt, hdr, hdr_end, 0);
    hdr[hdr_end] = '\0';

    /* Parse: "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n" */
    src_port = dst_port = 0;
    fields = sscanf(hdr + hdr_start, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);

    if (fields < 5 || memcmp(proto, "TCP4", 4) != 0) {
        shocst("PROXCLIP", spr("chan %02x: bad PROXY header (fields=%d), passing through", unum + 1, fields));
        return 0;
    }

    real_ip.s_addr = inet_addr(src_ip);
    if (real_ip.s_addr == INADDR_NONE) {
        shocst("PROXCLIP", spr("chan %02x: bad src IP in header, passing through", unum + 1));
        return 0;
    }

    (*pp_tcpipinf)[unum].inaddr = real_ip;
    shocst("PROXCLIP", spr("chan %02x: real IP %s", unum + 1, src_ip));
    return 1;
}

/*
 * proxclip_hdlcon
 *
 * Called by GALTNTD for every new telnet connection.
 *
 * Records the socket as pending for PROXY header processing, then hands
 * off to GALTNTD immediately via hcsave() -- no sleeping or polling.
 * When GALTNTD later calls recv() for this socket, prx_recv_hook fires
 * and consumes the PROXY header before GALTNTD sees any data.
 *
 * If the recv hook is unavailable (IAT patch failed), falls back to a
 * single non-blocking FIONREAD check as a best-effort measure.
 */
static VOID
proxclip_hdlcon(VOID)
{
    SOCKET skt;

    if (pp_tcpipinf == NULL || usrnum < 0 || usrnum >= nterms) {
        hcsave();
        return;
    }

    skt = (*pp_tcpipinf)[usrnum].socket;

    if (skt != INVALID_SOCKET) {
        if (real_recv != NULL) {
            /* Normal path: mark pending, hook will process on first recv. */
            pending_skt[usrnum] = skt;
        } else {
            /* Fallback: single non-blocking check right now. */
            u_long avail = 0;
            ioctlsocket(skt, FIONREAD, &avail);
            if (avail >= 6) {
                CHAR   hdr[128];
                INT    n, hdr_start, hdr_end, ii, fields;
                CHAR   proto[16], src_ip[64], dst_ip[64];
                INT    sp, dp;
                struct in_addr real_ip;

                n = recv(skt, hdr, (INT)(sizeof(hdr) - 1), MSG_PEEK);
                if (n >= 6) {
                    hdr[n] = '\0';
                    hdr_start = 0;
                    while (hdr_start < n && (hdr[hdr_start]=='\r' || hdr[hdr_start]=='\n'))
                        hdr_start++;
                    if ((n - hdr_start) >= 6 && memcmp(hdr + hdr_start, "PROXY ", 6) == 0) {
                        hdr_end = -1;
                        for (ii = 0; ii < n - 1; ii++) {
                            if (hdr[ii] == '\r' && hdr[ii+1] == '\n') {
                                hdr_end = ii + 2;
                                break;
                            }
                        }
                        if (hdr_end > 0) {
                            recv(skt, hdr, hdr_end, 0);
                            hdr[hdr_end] = '\0';
                            sp = dp = 0;
                            fields = sscanf(hdr + hdr_start,
                                            "PROXY %15s %63s %63s %d %d",
                                            proto, src_ip, dst_ip, &sp, &dp);
                            if (fields >= 5 && memcmp(proto, "TCP4", 4) == 0) {
                                real_ip.s_addr = inet_addr(src_ip);
                                if (real_ip.s_addr != INADDR_NONE) {
                                    (*pp_tcpipinf)[usrnum].inaddr = real_ip;
                                    shocst("PROXCLIP", spr("chan %02x: real IP %s (fallback)", usrnum + 1, src_ip));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    hcsave();
}

/*
 * proxclip_hup
 *
 * Clear the pending socket entry when a connection drops.  Prevents a
 * recycled socket handle on a new connection from matching a stale entry.
 */
static VOID
proxclip_hup(VOID)
{
    if (usrnum >= 0 && usrnum < MAXNTERM)
        pending_skt[usrnum] = INVALID_SOCKET;
}

/*
 * proxclip_fin
 *
 * Restore recv() IAT and hdlcon on shutdown.
 */
static VOID
proxclip_fin(VOID)
{
    if (patched_iat_entry != NULL && real_recv != NULL) {
        DWORD old_prot;
        VirtualProtect(patched_iat_entry, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
        *patched_iat_entry = real_recv;
        VirtualProtect(patched_iat_entry, sizeof(recv_fn_t), old_prot, &old_prot);
        patched_iat_entry = NULL;
        real_recv = NULL;
    }

    if (hcsave != NULL) {
        hdlcon = hcsave;
        hcsave = NULL;
    }
}
