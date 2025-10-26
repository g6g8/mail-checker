#!/usr/bin/env python3
"""
mailserver_check_pushover.py

Same as the original mailserver_check script, but minimal changes to notify via Pushover
when urgent issues are found.

Prereqs:
    pip install dnspython requests
"""

import os
import argparse
import socket
import ssl
import smtplib
import imaplib
import poplib
import datetime
import json
import sys
import traceback
from typing import Dict, Any, List, Optional

import dns.resolver
import requests

# -------------------------
# Helpers
# -------------------------
def utcnow():
    return datetime.datetime.utcnow()

def parse_cert_notAfter(notAfter_str: str) -> datetime.datetime:
    # Example format: 'Jul  1 12:00:00 2026 GMT'
    return datetime.datetime.strptime(notAfter_str, "%b %d %H:%M:%S %Y %Z")

def get_remote_certificate(host: str, port: int = 443, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """Return certificate dict with subject, issuer, notAfter (datetime), raw pem, or None on error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                cert = ssock.getpeercert()
                not_after = None
                if 'notAfter' in cert:
                    try:
                        not_after = parse_cert_notAfter(cert['notAfter'])
                    except Exception:
                        not_after = None
                return {"pem": pem, "cert": cert, "notAfter": not_after}
    except Exception:
        return None

# -------------------------
# Mail checks
# -------------------------
def check_smtps(host: str, port: int = 465, timeout: int = 10) -> Dict[str, Any]:
    result = {"name": f"SMTPS ({port})", "ok": False, "error": None, "cert_expires": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                if cert and 'notAfter' in cert:
                    try:
                        na = parse_cert_notAfter(cert['notAfter'])
                        result["cert_expires"] = na.isoformat()
                    except Exception:
                        pass
                result["ok"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result

def check_smtp_starttls(host: str, port: int = 587, timeout: int = 10) -> Dict[str, Any]:
    result = {"name": f"SMTP+STARTTLS ({port})", "ok": False, "error": None, "tls_ok": False, "cert_expires": None}
    try:
        with smtplib.SMTP(host=host, port=port, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            if smtp.has_extn('starttls'):
                ctx = ssl.create_default_context()
                smtp.starttls(context=ctx)
                smtp.ehlo()
                result["tls_ok"] = True
                sock = smtp.sock
                try:
                    cert = sock.getpeercert()
                    if cert and 'notAfter' in cert:
                        na = parse_cert_notAfter(cert['notAfter'])
                        result["cert_expires"] = na.isoformat()
                except Exception:
                    pass
                result["ok"] = True
            else:
                result["error"] = "STARTTLS not advertised by server"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result

def check_imaps(host: str, port: int = 993, timeout: int = 10) -> Dict[str, Any]:
    result = {"name": f"IMAPS ({port})", "ok": False, "error": None, "cert_expires": None}
    try:
        imap = imaplib.IMAP4_SSL(host=host, port=port, timeout=timeout)
        result["ok"] = True
        try:
            sock = imap.socket()
            if hasattr(sock, "getpeercert"):
                cert = sock.getpeercert()
                if cert and 'notAfter' in cert:
                    na = parse_cert_notAfter(cert['notAfter'])
                    result["cert_expires"] = na.isoformat()
        except Exception:
            pass
        try:
            imap.logout()
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result

def check_pop3s(host: str, port: int = 995, timeout: int = 10) -> Dict[str, Any]:
    result = {"name": f"POP3S ({port})", "ok": False, "error": None, "cert_expires": None}
    try:
        p = poplib.POP3_SSL(host=host, port=port, timeout=timeout)
        result["ok"] = True
        try:
            ss = p._sock
            if hasattr(ss, "getpeercert"):
                cert = ss.getpeercert()
                if cert and 'notAfter' in cert:
                    na = parse_cert_notAfter(cert['notAfter'])
                    result["cert_expires"] = na.isoformat()
        except Exception:
            pass
        try:
            p.quit()
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result

def check_mx(domain: str, resolver_timeout: int = 5) -> Dict[str, Any]:
    res = {"name": "MX lookup", "ok": False, "error": None, "mx": []}
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=resolver_timeout)
        mxs = []
        for r in answers:
            mxs.append((int(r.preference), str(r.exchange).rstrip('.')))
        mxs.sort()
        res["mx"] = mxs
        res["ok"] = True if mxs else False
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    return res

# -------------------------
# Pushover notification (minimal add)
# -------------------------
def send_pushover(app_token: str, user_key: str, message: str, title: Optional[str] = None,
                  device: Optional[str] = None, priority: int = 0, sound: Optional[str] = None,
                  timeout: int = 8) -> Dict[str, Any]:
    """
    Send a notification via Pushover.
    Returns dict with 'ok' boolean and response details.
    """
    url = "https://api.pushover.net/1/messages.json"
    data = {
        "token": app_token,
        "user": user_key,
        "message": message,
        "priority": str(priority)
    }
    if title:
        data["title"] = title
    if device:
        data["device"] = device
    if sound:
        data["sound"] = sound
    try:
        r = requests.post(url, data=data, timeout=timeout)
        return {"ok": r.ok, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

# -------------------------
# Runner / summary / report (unchanged)
# -------------------------
def run_checks(target: str, check_mx_flag: bool = True, ports_timeout: int = 10) -> List[Dict[str, Any]]:
    results = []
    if check_mx_flag and '.' in target and not target.replace('.', '').isdigit():
        mxres = check_mx(target)
        results.append(mxres)
        if mxres.get("ok") and mxres.get("mx"):
            mx_host = mxres["mx"][0][1]
        else:
            mx_host = target
    else:
        mx_host = target

    results.append(check_smtps(mx_host, port=465, timeout=ports_timeout))
    #results.append(check_smtp_starttls(mx_host, port=587, timeout=ports_timeout))
    results.append(check_smtp_starttls(mx_host, port=25, timeout=ports_timeout))
    results.append(check_imaps(mx_host, port=993, timeout=ports_timeout))
    #results.append(check_pop3s(mx_host, port=995, timeout=ports_timeout))
    certinfo = get_remote_certificate(mx_host, port=465, timeout=ports_timeout) or get_remote_certificate(mx_host, port=993, timeout=ports_timeout)
    if certinfo:
        if certinfo.get("notAfter"):
            results.append({"name": "TLS cert (probe)", "ok": True, "notAfter": certinfo["notAfter"].isoformat()})
        else:
            results.append({"name": "TLS cert (probe)", "ok": True, "info": "cert retrieved"})
    else:
        results.append({"name": "TLS cert (probe)", "ok": False, "error": "unable to fetch cert"})
    return results

def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    issues = []
    warnings = []
    for r in results:
        if not r.get("ok", False):
            issues.append(r)
        else:
            na = None
            if r.get("cert_expires"):
                try:
                    na = datetime.datetime.fromisoformat(r["cert_expires"])
                except Exception:
                    pass
            if not na and r.get("notAfter"):
                try:
                    na = datetime.datetime.fromisoformat(r["notAfter"])
                except Exception:
                    pass
            if na:
                days = (na - utcnow()).days
                if days < 0:
                    issues.append({"name": r.get("name", "unknown"), "error": f"certificate expired on {na.isoformat()}"})
                elif days <= 14:
                    warnings.append({"name": r.get("name", "unknown"), "warning": f"certificate expires in {days} days ({na.date().isoformat()})"})
    return {"issues": issues, "warnings": warnings}

def build_text_report(target: str, results: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"Mail server check report for {target}")
    lines.append(f"Checked at (UTC): {utcnow().isoformat()}")
    lines.append("")
    for r in results:
        name = r.get("name")
        ok = r.get("ok")
        lines.append(f"- {name}: {'OK' if ok else 'FAIL'}")
        if not ok:
            lines.append(f"    Error: {r.get('error')}")
        if r.get("cert_expires"):
            lines.append(f"    Cert expires: {r.get('cert_expires')}")
        if r.get("mx"):
            lines.append(f"    MX: {r['mx']}")
    lines.append("")
    if summary["warnings"]:
        lines.append("Warnings:")
        for w in summary["warnings"]:
            lines.append(f"  * {w.get('name')}: {w.get('warning')}")
    if summary["issues"]:
        lines.append("Issues (urgent):")
        for i in summary["issues"]:
            lines.append(f"  * {i.get('name')}: {i.get('error')}")
    if not summary["issues"] and not summary["warnings"]:
        lines.append("No issues detected.")
    return "\n".join(lines)

# -------------------------
# CLI / main (modified minimally to accept pushover args)
# -------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Mail server tester + Pushover notifier (minimal changes)")
    parser.add_argument("--host", "-H", default=os.getenv("MAILSERVER"), help="Mail server hostname to test (or domain to MX lookup)")
    parser.add_argument("--check-mx", action="store_true", default=False, help="Also perform MX lookup for the domain and test the MX host (default: off)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeouts (seconds) for network ops")

    # Pushover args (minimal addition)
    parser.add_argument("--pushover-token", default=os.getenv("PUSHOVER_TOKEN"), help="Pushover application token (required to send pushover)")
    parser.add_argument("--pushover-user", default=os.getenv("PUSHOVER_USER"), help="Pushover user key (required to send pushover)")
    parser.add_argument("--pushover-device", help="Optional Pushover device name to target")
    parser.add_argument("--pushover-priority", type=int, choices=[-2, -1, 0, 1, 2], default=0, help="Pushover priority (-2..2), default 0")
    parser.add_argument("--pushover-sound", help="Optional Pushover sound name")

    args = parser.parse_args(argv)

    try:
        print(f"Testing host {args.host}")
        results = run_checks(args.host, check_mx_flag=args.check_mx, ports_timeout=args.timeout)
        summary = summarize_results(results)
        report = build_text_report(args.host, results, summary)
        print(report)

        if summary["issues"]:
            # Build a concise message for Pushover (Pushover messages should be short)
            short_msg = f"URGENT: mailserver issues for {args.host} - {len(summary['issues'])} issue(s)."
            if args.pushover_token and args.pushover_user:
                # include report truncated as the 'message' body if desired; here we send a short message + attach full report in 'message' (ok)
                payload_message = short_msg + "\n\n" + "\n".join(line for line in report.splitlines()[:12])  # keep first 12 lines
                resp = send_pushover(
                    app_token=args.pushover_token,
                    user_key=args.pushover_user,
                    message=payload_message,
                    title=f"Mail check {args.host}",
                    device=args.pushover_device,
                    priority=args.pushover_priority,
                    sound=args.pushover_sound
                )
                print(f"[notification] Pushover -> {resp}")
            else:
                print("[notification] Pushover credentials not provided; no Pushover notification sent.")
        else:
            print("No urgent issues — no notifications sent.")
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
    except Exception:
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()

