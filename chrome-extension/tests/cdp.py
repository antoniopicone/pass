"""Minimal Chrome DevTools Protocol client used by run_tests.py.

Requires the `websocket-client` package (see requirements.txt) — pure
stdlib `urllib` handles the HTTP /json endpoints, but CDP's actual command
channel is a WebSocket.
"""

import json
import time
import urllib.request
import websocket

BASE = "http://localhost:9333"


def http_json(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.loads(r.read())


class Target:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=15)
        self._id = 0
        self.events = []  # collected notification-type messages (no "id")

    def send(self, method, params=None, timeout=15):
        self._id += 1
        my_id = self._id
        self.ws.send(json.dumps({"id": my_id, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            raw = self.ws.recv()
            msg = json.loads(raw)
            if msg.get("id") == my_id:
                if "error" in msg:
                    raise RuntimeError(f"{method} error: {msg['error']}")
                return msg.get("result", {})
            elif "method" in msg:
                self.events.append(msg)
        raise TimeoutError(f"timeout waiting for {method}")

    def eval(self, expression, await_promise=False, timeout=15):
        res = self.send(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": await_promise},
            timeout=timeout,
        )
        if res.get("exceptionDetails"):
            raise RuntimeError(f"JS error: {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    def drain(self, duration=1.0):
        """Collect notification events for `duration` seconds."""
        self.ws.settimeout(duration)
        end = time.time() + duration
        try:
            while time.time() < end:
                raw = self.ws.recv()
                msg = json.loads(raw)
                if "method" in msg:
                    self.events.append(msg)
        except Exception:
            pass
        finally:
            self.ws.settimeout(15)

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def open_tab(url):
    req = urllib.request.Request(BASE + "/json/new?" + url, method="PUT")
    try:
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError:
        req = urllib.request.Request(BASE + "/json/new?" + url, method="POST")
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
    return data["id"], Target(data["webSocketDebuggerUrl"])


def close_tab(tab_id):
    try:
        urllib.request.urlopen(BASE + "/json/close/" + tab_id)
    except Exception:
        pass


def send_to_background(t, ext_id, msg_type, payload=None):
    """Sends a chrome.runtime.sendMessage to the extension's background
    service worker from within `t` (must be an extension-origin context,
    e.g. the popup or a content-script world), mirroring popup.js/content.js's
    own sendToBackground helper. Returns the `result` field of the response."""
    payload_json = json.dumps(payload or {})
    expr = f"""
    new Promise((resolve) => {{
      chrome.runtime.sendMessage({{type: {json.dumps(msg_type)}, payload: {payload_json}}}, (r) => resolve(JSON.stringify(r)));
    }})
    """
    raw = t.eval(expr, await_promise=True)
    res = json.loads(raw)
    if not res.get("ok"):
        raise RuntimeError(f"{msg_type} failed: {res.get('error')}")
    return res.get("result")
