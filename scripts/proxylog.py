#!/usr/bin/env python3
"""Tiny logging proxy: forwards to an upstream OpenAI-compatible endpoint and records
the last few request/response bodies, so a flaky or truncated model answer can be seen.

    python3 scripts/proxylog.py --listen 11435 --upstream https://text.pollinations.ai/openai --log /tmp/proxy.log
"""
import argparse
import json
import os
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    upstream = ""
    log_path = ""
    keep = 5

    def do_GET(self):
        req = urllib.request.Request(self.upstream + self.path)
        key = self.headers.get("Authorization")
        if key:
            req.add_header("Authorization", key)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                body = r.read()
                self.send_response(r.status)
                self.send_header("Content-Type", r.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(e.read())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        req = urllib.request.Request(self.upstream + self.path, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        key = self.headers.get("Authorization")
        if key:
            req.add_header("Authorization", key)
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                resp = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            resp = e.read()
            status = e.code
        except Exception as e:  # noqa: BLE001 - the proxy must never die
            resp = json.dumps({"error": {"message": str(e)}}).encode()
            status = 502

        self._record(body, resp, status, time.time() - started)

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def _record(self, req_body, resp_body, status, took):
        try:
            req_json = json.loads(req_body)
            resp_json = json.loads(resp_body)
        except Exception:  # noqa: BLE001
            req_json, resp_json = {}, {}
        choice = (resp_json.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content") or ""
        reasoning = msg.get("reasoning") or ""
        entry = {
            "at": time.strftime("%H:%M:%S"),
            "status": status,
            "took_s": round(took, 1),
            "model": req_json.get("model"),
            "reasoning_effort": req_json.get("reasoning_effort"),
            "prompt_chars": len(req_json.get("messages", [{}])[-1].get("content", "")) if req_json.get("messages") else 0,
            "finish_reason": choice.get("finish_reason"),
            "completion_tokens": (resp_json.get("usage") or {}).get("completion_tokens"),
            "reasoning_len": len(reasoning),
            "content_len": len(content),
            "content_head": content[:1200],
        }
        with open(self.log_path, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def log_message(self, *args):  # silence the default stderr access log
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=11435)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--log", default="/tmp/proxy.log")
    args = ap.parse_args()

    Handler.upstream = args.upstream.rstrip("/")
    Handler.log_path = args.log
    if os.path.exists(args.log):
        os.remove(args.log)

    server = HTTPServer(("127.0.0.1", args.listen), Handler)
    print(f"proxy on http://127.0.0.1:{args.listen} -> {Handler.upstream}, logging to {args.log}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
