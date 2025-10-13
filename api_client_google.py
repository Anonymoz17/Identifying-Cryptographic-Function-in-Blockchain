# api_client_google.py
import threading, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from typing import Tuple, Optional, Dict, Any
from api_client_supabase import _sb  # reuse your initialized client

def _start_callback_server(start_port: int = 8750, try_ports: int = 10):
    server = None; chosen = None
    class Handler(BaseHTTPRequestHandler):
        done_event = None
        result = {"code": None, "error": None}
        def do_GET(self):
            p = urlparse(self.path)
            if p.path != "/auth/callback":
                self.send_response(404); self.end_headers(); return
            qs = parse_qs(p.query)
            code = (qs.get("code") or [None])[0]
            err  = (qs.get("error_description") or qs.get("error") or [None])[0]
            if code:
                type(self).result["code"] = code
                msg = "Sign-in successful. You can close this window."
            else:
                type(self).result["error"] = err or "Missing 'code' in callback."
                msg = "Sign-in failed. You can close this window."
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(f"<html><body><p>{msg}</p></body></html>".encode("utf-8"))
            type(self).done_event.set()
        def log_message(self, *_): return
    for port in range(start_port, start_port+try_ports):
        try:
            server = HTTPServer(("127.0.0.1", port), Handler); chosen = port; break
        except OSError: continue
    if not server: raise RuntimeError("Could not bind a local callback port.")
    return server, f"http://127.0.0.1:{chosen}/auth/callback", Handler

def login_with_google(port: int = 8750, timeout_sec: int = 180) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    try:
        server, redirect_to, Handler = _start_callback_server(port)
    except Exception as e:
        return False, f"Callback server error: {e}", None
    Handler.done_event = threading.Event()

    try:
        resp = _sb.auth.sign_in_with_oauth({"provider":"google","options":{"redirect_to":redirect_to}})
        auth_url = getattr(resp, "url", None) or (resp.get("url") if isinstance(resp, dict) else None)
        if not auth_url: return False, "No OAuth URL returned by Supabase.", None
    except Exception as e:
        return False, f"OAuth start failed: {e}", None

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try: webbrowser.open(auth_url)
    except Exception: pass

    if not Handler.done_event.wait(timeout=timeout_sec):
        try: server.shutdown()
        except Exception: pass
        return False, "Timed out waiting for Google sign-in.", None
    try: server.shutdown()
    except Exception: pass

    if Handler.result.get("error"):
        return False, str(Handler.result["error"]), None

    try:
        ex = _sb.auth.exchange_code_for_session({"auth_code": Handler.result["code"]})
        session = getattr(ex, "session", None) or (ex.get("session") if isinstance(ex, dict) else None)
        if not session: return False, "No session returned from code exchange.", None
        token = session.access_token
        user  = getattr(ex, "user", None) or getattr(session, "user", None)
        return True, token, {"id": str(getattr(user, "id", "")), "email": getattr(user, "email", None)}
    except Exception as e:
        return False, f"Code exchange failed: {e}", None
