import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def load_env(path=ENV_PATH):
    if not Path(path).exists():
        return
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env()

HOST = os.getenv("CRYPTO_BACKEND_HOST", "0.0.0.0")
PORT = int(os.getenv("CRYPTO_BACKEND_PORT", "8787"))
DATABASE_PATH = BASE_DIR / os.getenv("CRYPTO_DATABASE_PATH", "crypto_deposits.sqlite3")
WEB_APP_ORIGIN = os.getenv("WEB_APP_ORIGIN", "https://bucolic-paprenjak-5d3093.netlify.app")
BACKEND_PUBLIC_URL = os.getenv("BACKEND_PUBLIC_URL", "").rstrip("/")
NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_IPN_SECRET = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
NOWPAYMENTS_API_BASE = os.getenv("NOWPAYMENTS_API_BASE", "https://api.nowpayments.io")
NC_PER_USDT = int(os.getenv("NC_PER_USDT", "10"))

PAID_STATUSES = {"confirmed", "finished", "sending", "partially_paid"}


def setup_database():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                usdt_amount REAL NOT NULL,
                nc_amount INTEGER NOT NULL,
                provider_payment_id TEXT,
                invoice_url TEXT,
                status TEXT NOT NULL DEFAULT 'waiting',
                credited INTEGER NOT NULL DEFAULT 0,
                raw_provider_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS balances (
                user_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
            """
        )


def json_response(handler, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", WEB_APP_ORIGIN)
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, x-nowpayments-sig")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    return raw, json.loads(raw.decode("utf-8") or "{}")


def stable_json_for_signature(raw_body):
    payload = json.loads(raw_body.decode("utf-8") or "{}")
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_nowpayments_signature(raw_body, signature):
    if not NOWPAYMENTS_IPN_SECRET:
        return False
    digest = hmac.new(
        NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
        stable_json_for_signature(raw_body),
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(digest, signature or "")


def create_nowpayments_invoice(order_id, usdt_amount):
    if not NOWPAYMENTS_API_KEY:
        raise RuntimeError("NOWPAYMENTS_API_KEY is missing in .env")
    if not BACKEND_PUBLIC_URL:
        raise RuntimeError("BACKEND_PUBLIC_URL is missing in .env")

    payload = {
        "price_amount": usdt_amount,
        "price_currency": "usd",
        "pay_currency": "usdttrc20",
        "order_id": order_id,
        "order_description": "YouWin USDT top up",
        "ipn_callback_url": f"{BACKEND_PUBLIC_URL}/api/deposit/webhook/nowpayments",
        "success_url": WEB_APP_ORIGIN,
        "cancel_url": WEB_APP_ORIGIN,
    }
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{NOWPAYMENTS_API_BASE}/v1/invoice",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": NOWPAYMENTS_API_KEY,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=35) as response:
        return json.loads(response.read().decode("utf-8"))


def credit_deposit(order_id, provider_status, raw_payload):
    now = int(time.time())
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        deposit = conn.execute(
            "SELECT * FROM deposits WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        if not deposit:
            return {"credited": False, "reason": "unknown_order"}

        already_credited = bool(deposit["credited"])
        should_credit = provider_status in PAID_STATUSES and not already_credited
        if should_credit:
            conn.execute(
                """
                INSERT INTO balances (user_id, balance, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    balance = balance + excluded.balance,
                    updated_at = excluded.updated_at
                """,
                (deposit["user_id"], deposit["nc_amount"], now),
            )

        conn.execute(
            """
            UPDATE deposits
            SET status = ?, credited = CASE WHEN ? THEN 1 ELSE credited END,
                raw_provider_json = ?, updated_at = ?
            WHERE order_id = ?
            """,
            (provider_status, int(should_credit), json.dumps(raw_payload), now, order_id),
        )

    return {"credited": should_credit, "already_credited": already_credited}


class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        json_response(self, 200, {"ok": True})

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)

        if url.path == "/api/health":
            json_response(self, 200, {"ok": True, "service": "youwin-crypto-backend"})
            return

        if url.path == "/api/deposit/status":
            deposit_id = params.get("deposit_id", [""])[0]
            with sqlite3.connect(DATABASE_PATH) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT status, credited, nc_amount FROM deposits WHERE id = ?",
                    (deposit_id,),
                ).fetchone()
            if not row:
                json_response(self, 404, {"ok": False, "error": "deposit_not_found"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "status": row["status"],
                    "credited": bool(row["credited"]),
                    "nc_amount": row["nc_amount"],
                },
            )
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        raw_body, payload = read_json(self)

        if url.path == "/api/deposit/create":
            try:
                user_id = str(payload.get("user_id", "")).strip()
                usdt_amount = float(payload.get("usdt_amount", 0))
                if not user_id:
                    raise ValueError("user_id_required")
                if usdt_amount <= 0:
                    raise ValueError("amount_must_be_positive")

                nc_amount = int(usdt_amount * NC_PER_USDT)
                order_id = f"YW-{user_id}-{int(time.time())}"
                provider = create_nowpayments_invoice(order_id, usdt_amount)
                invoice_url = (
                    provider.get("invoice_url")
                    or provider.get("payment_url")
                    or provider.get("pay_url")
                    or provider.get("url")
                )
                provider_payment_id = str(provider.get("id") or provider.get("payment_id") or "")
                now = int(time.time())
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO deposits (
                            order_id, user_id, usdt_amount, nc_amount,
                            provider_payment_id, invoice_url, raw_provider_json,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            order_id,
                            user_id,
                            usdt_amount,
                            nc_amount,
                            provider_payment_id,
                            invoice_url,
                            json.dumps(provider),
                            now,
                            now,
                        ),
                    )
                    deposit_id = cursor.lastrowid

                json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "deposit_id": deposit_id,
                        "order_id": order_id,
                        "invoice_url": invoice_url,
                        "usdt_amount": usdt_amount,
                        "nc_amount": nc_amount,
                    },
                )
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/deposit/webhook/nowpayments":
            signature = self.headers.get("x-nowpayments-sig", "")
            if not verify_nowpayments_signature(raw_body, signature):
                json_response(self, 401, {"ok": False, "error": "bad_signature"})
                return

            order_id = str(payload.get("order_id", ""))
            status = str(payload.get("payment_status", payload.get("status", ""))).lower()
            result = credit_deposit(order_id, status, payload)
            json_response(self, 200, {"ok": True, **result})
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


def main():
    setup_database()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"YouWin crypto backend running on http://{HOST}:{PORT}")
    print("Webhook URL:", f"{BACKEND_PUBLIC_URL}/api/deposit/webhook/nowpayments")
    server.serve_forever()


if __name__ == "__main__":
    main()

