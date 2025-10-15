# api_client_github.py
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from api_client_supabase import _sb  # your existing client


def _start_callback_server(port: int = 8750):
    class Handler(BaseHTTPRequestHandler):
        done = None  # threading.Event
        result = {"code": None, "error": None}

        def do_GET(self):
            p = urlparse(self.path)
            if p.path != "/auth/callback":
                self.send_response(404)
                self.end_headers()
                return
            q = parse_qs(p.query)
            Handler.result["code"] = q.get("code", [None])[0]
            Handler.result["error"] = q.get(
                "error_description", q.get("error", [None])
            )[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Sign-in successful. You can close this window.")
            Handler.done.set()

        def log_message(self, *a, **k):
            return

    server = HTTPServer(("127.0.0.1", port), Handler)
    return server, Handler


def login_with_github(
    port: int = 8750, timeout_sec: int = 180
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    # 1) Start local callback
    server, Handler = _start_callback_server(port)
    Handler.done = threading.Event()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    redirect_url = f"http://127.0.0.1:{port}/auth/callback"

    # 2) Begin OAuth
    try:
        resp = _sb.auth.sign_in_with_oauth(
            {"provider": "github", "options": {"redirect_to": redirect_url}}
        )
        auth_url = getattr(resp, "url", None) or (
            resp.get("url") if isinstance(resp, dict) else None
        )
        if not auth_url:
            return False, "No OAuth URL from Supabase", None
    except Exception as e:
        return False, f"OAuth start failed: {e}", None

    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    # 3) Wait for callback
    if not Handler.done.wait(timeout_sec):
        try:
            server.shutdown()
        except Exception:
            pass
        return False, "Timed out waiting for GitHub sign-in.", None
    try:
        server.shutdown()
    except Exception:
        pass

    if Handler.result["error"]:
        return False, str(Handler.result["error"]), None

    # 4) Exchange code for session
    code = Handler.result["code"]
    try:
        ex = _sb.auth.exchange_code_for_session({"auth_code": code})
        session = getattr(ex, "session", None) or (
            ex.get("session") if isinstance(ex, dict) else None
        )
        userobj = getattr(ex, "user", None) or getattr(session, "user", None)
        if not session:
            return False, "No session returned from code exchange.", None

        token = session.access_token
        # GitHub email can be empty/private; make it a safe string
        email = getattr(userobj, "email", None) or ""
        uid = str(getattr(userobj, "id", "")) if userobj else ""
        return True, token, {"id": uid, "email": email}
    except Exception as e:
        return False, f"Code exchange failed: {e}", None
