import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
from decimal import Decimal, ROUND_DOWN
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
PORT = int(os.getenv("PORT", os.getenv("CRYPTO_BACKEND_PORT", "8787")))
DATABASE_PATH = BASE_DIR / os.getenv("CRYPTO_DATABASE_PATH", "crypto_deposits.sqlite3")
WEB_APP_ORIGIN = os.getenv("WEB_APP_ORIGIN", "https://bucolic-paprenjak-5d3093.netlify.app")
WEB_APP_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.getenv("WEB_APP_ORIGINS", WEB_APP_ORIGIN).split(",")
    if origin.strip()
}
BACKEND_PUBLIC_URL = os.getenv("BACKEND_PUBLIC_URL", "").rstrip("/")
PAYMENT_PROVIDER = os.getenv("PAYMENT_PROVIDER", "cryptopay").strip().lower()
CRYPTO_PAY_API_TOKEN = os.getenv("CRYPTO_PAY_API_TOKEN", "")
CRYPTO_PAY_API_BASE = os.getenv("CRYPTO_PAY_API_BASE", "https://pay.crypt.bot")
CRYPTO_PAY_ASSET = os.getenv("CRYPTO_PAY_ASSET", "USDT")
TELEGRAM_WALLET_URL = os.getenv("TELEGRAM_WALLET_URL", "https://t.me/wallet")
CRYPTO_PAY_PAID_STATUSES = {"paid"}
SUPPORTED_CRYPTO_PAY_ASSETS = {"USDT", "TON", "BTC", "ETH"}
SUPPORTED_PROVIDERS = {"cryptopay", "direct_crypto"}
DIRECT_WALLETS = {
    "USDT": {
        "TRC20": os.getenv("DIRECT_USDT_TRC20_ADDRESS", "THX7cd5voYJKHGKwhcA7SWwsqBJT8HTepB"),
        "ERC20": os.getenv("DIRECT_USDT_ERC20_ADDRESS", "0x3efeDfFaD839006b3DDa4543fcd6b1909f8Ba9E7"),
    },
    "TON": {
        "TON": os.getenv("DIRECT_TON_ADDRESS", "UQCf82JLZi2zzfQ_zGnzTNDGaL4MJVEFtA7kuA4ks07q00Vg"),
    },
    "BTC": {
        "BTC": os.getenv("DIRECT_BTC_ADDRESS", "bc1q4pl0q29yvpl3ut6rpvcjvkcxr8sh3swxpafthv"),
    },
    "ETH": {
        "ERC20": os.getenv("DIRECT_ETH_ADDRESS", "0x3efeDfFaD839006b3DDa4543fcd6b1909f8Ba9E7"),
    },
}


def setup_database():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                usdt_amount REAL NOT NULL,
                nc_amount REAL NOT NULL,
                crypto_asset TEXT NOT NULL DEFAULT 'USDT',
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
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(deposits)").fetchall()
        }
        if "provider" not in columns:
            conn.execute("ALTER TABLE deposits ADD COLUMN provider TEXT NOT NULL DEFAULT 'cryptopay'")
        if "crypto_asset" not in columns:
            conn.execute("ALTER TABLE deposits ADD COLUMN crypto_asset TEXT NOT NULL DEFAULT 'USDT'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS balances (
                user_id TEXT PRIMARY KEY,
                balance REAL NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS asset_balances (
                user_id TEXT NOT NULL,
                asset TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, asset)
            )
            """
        )


def json_response(handler, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request_origin = handler.headers.get("Origin", "").rstrip("/")
    allow_origin = request_origin if request_origin in WEB_APP_ORIGINS else WEB_APP_ORIGIN.rstrip("/")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", allow_origin)
    handler.send_header("Vary", "Origin")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, crypto-pay-api-signature")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def redirect_response(handler, location):
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def read_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    return raw, json.loads(raw.decode("utf-8") or "{}")


def verify_crypto_pay_signature(raw_body, signature):
    if not CRYPTO_PAY_API_TOKEN:
        return False
    secret = hashlib.sha256(CRYPTO_PAY_API_TOKEN.encode("utf-8")).digest()
    digest = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature or "")


def clean_crypto_asset(asset):
    asset = str(asset or CRYPTO_PAY_ASSET or "USDT").strip().upper()
    return asset if asset in SUPPORTED_CRYPTO_PAY_ASSETS else "USDT"


def clean_provider(provider):
    provider = str(provider or PAYMENT_PROVIDER or "cryptopay").strip().lower()
    return provider if provider in SUPPORTED_PROVIDERS else "cryptopay"


def clean_direct_network(asset, network=None):
    asset = clean_crypto_asset(asset)
    network = str(network or "").strip().upper()
    available = DIRECT_WALLETS.get(asset, {})
    if network in available:
        return network
    return next(iter(available.keys()), asset)


def format_crypto_amount(value):
    quantized = Decimal(str(value)).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
    return format(quantized.normalize(), "f")


def direct_unique_amount(base_amount, order_id, crypto_asset):
    decimals = Decimal("0.00000001") if crypto_asset in {"BTC", "ETH"} else Decimal("0.0001")
    tail = (int(hashlib.sha1(order_id.encode("utf-8")).hexdigest()[:6], 16) % 7000) + 1000
    multiplier = Decimal(tail) if crypto_asset in {"BTC", "ETH"} else Decimal(tail % 900 + 100)
    return (Decimal(str(base_amount)) + decimals * multiplier).quantize(decimals, rounding=ROUND_DOWN)


def http_get_json(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.loads(response.read().decode("utf-8"))


def crypto_pay_api(method, payload=None):
    body = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(
        f"{CRYPTO_PAY_API_BASE.rstrip('/')}/api/{method}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "YouWinMiniApp/1.0 (+https://youwin-backend.onrender.com)",
            "Crypto-Pay-API-Token": CRYPTO_PAY_API_TOKEN,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Crypto Pay HTTP {error.code}: {details}") from error

    if not data.get("ok"):
        raise RuntimeError(f"Crypto Pay error: {json.dumps(data, ensure_ascii=False)}")
    return data.get("result")


def create_crypto_pay_invoice(order_id, pay_amount, crypto_asset=None):
    if not CRYPTO_PAY_API_TOKEN:
        raise RuntimeError("CRYPTO_PAY_API_TOKEN is missing in environment variables")
    if not BACKEND_PUBLIC_URL:
        raise RuntimeError("BACKEND_PUBLIC_URL is missing in environment variables")

    crypto_asset = clean_crypto_asset(crypto_asset)
    crypto_amount = format_crypto_amount(pay_amount)
    payload = {
        "asset": crypto_asset,
        "amount": crypto_amount,
        "description": f"YouWin {crypto_amount} {crypto_asset} top up",
        "payload": order_id,
        "expires_in": 3600,
    }
    provider = crypto_pay_api("createInvoice", payload) or {}
    provider["youwin_pay_amount"] = pay_amount
    provider["youwin_crypto_asset"] = crypto_asset
    provider["youwin_crypto_amount"] = crypto_amount
    return provider


def create_provider_invoice(provider, order_id, usdt_amount, crypto_asset=None):
    provider = clean_provider(provider)
    return create_crypto_pay_invoice(order_id, usdt_amount, crypto_asset)


def create_direct_crypto_payment(user_id, amount, crypto_asset, network=None):
    crypto_asset = clean_crypto_asset(crypto_asset)
    network = clean_direct_network(crypto_asset, network)
    address = DIRECT_WALLETS.get(crypto_asset, {}).get(network, "")
    if not address:
        raise RuntimeError(f"direct_wallet_missing:{crypto_asset}")

    order_id = f"YW-DIRECT-{user_id}-{int(time.time())}"
    pay_amount = direct_unique_amount(amount, order_id, crypto_asset)
    now = int(time.time())
    details = {
        "provider": "direct_crypto",
        "order_id": order_id,
        "asset": crypto_asset,
        "network": network,
        "address": address,
        "requested_amount": float(amount),
        "pay_amount": float(pay_amount),
    }
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO deposits (
                order_id, user_id, usdt_amount, nc_amount,
                crypto_asset, provider, provider_payment_id, invoice_url, raw_provider_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_id,
                user_id,
                float(pay_amount),
                float(pay_amount),
                crypto_asset,
                "direct_crypto",
                "",
                "",
                json.dumps(details),
                now,
                now,
            ),
        )
        details["deposit_id"] = cursor.lastrowid
    return details


def check_direct_payment(deposit):
    details = json.loads(deposit["raw_provider_json"] or "{}")
    asset = str(deposit["crypto_asset"]).upper()
    network = str(details.get("network") or clean_direct_network(asset)).upper()
    address = details.get("address", "")
    expected = Decimal(str(deposit["usdt_amount"]))
    created_at = int(deposit["created_at"] or 0) - 180

    if asset == "USDT" and network == "TRC20":
        url = (
            f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20"
            "?limit=50&contract_address=TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcd"
        )
        headers = {}
        if os.getenv("TRONGRID_API_KEY"):
            headers["TRON-PRO-API-KEY"] = os.getenv("TRONGRID_API_KEY")
        data = http_get_json(url, headers)
        for tx in data.get("data", []):
            if str(tx.get("to", "")).lower() != address.lower():
                continue
            if int(tx.get("block_timestamp", 0)) // 1000 < created_at:
                continue
            decimals = int(tx.get("token_info", {}).get("decimals", 6))
            amount = Decimal(str(tx.get("value", "0"))) / (Decimal(10) ** decimals)
            if amount >= expected:
                return {"found": True, "txid": tx.get("transaction_id"), "amount": float(amount), "raw": tx}

    if asset == "USDT" and network == "ERC20":
        api_key = os.getenv("ETHERSCAN_API_KEY", "")
        url = (
            "https://api.etherscan.io/api?module=account&action=tokentx"
            "&contractaddress=0xdAC17F958D2ee523a2206206994597C13D831ec7"
            f"&address={address}&sort=desc&page=1&offset=50&apikey={api_key}"
        )
        data = http_get_json(url)
        for tx in data.get("result", []):
            if str(tx.get("to", "")).lower() != address.lower():
                continue
            if int(tx.get("timeStamp", 0)) < created_at:
                continue
            decimals = int(tx.get("tokenDecimal", 6))
            amount = Decimal(str(tx.get("value", 0))) / (Decimal(10) ** decimals)
            if amount >= expected:
                return {"found": True, "txid": tx.get("hash"), "amount": float(amount), "raw": tx}

    if asset == "BTC":
        data = http_get_json(f"https://mempool.space/api/address/{address}/txs")
        for tx in data[:50]:
            block_time = int(tx.get("status", {}).get("block_time") or time.time())
            if block_time < created_at:
                continue
            total = Decimal("0")
            for out in tx.get("vout", []):
                if out.get("scriptpubkey_address") == address:
                    total += Decimal(str(out.get("value", 0))) / Decimal("100000000")
            if total >= expected:
                return {"found": True, "txid": tx.get("txid"), "amount": float(total), "raw": tx}

    if asset == "TON":
        data = http_get_json(f"https://tonapi.io/v2/blockchain/accounts/{address}/transactions?limit=30")
        for tx in data.get("transactions", []):
            now_ts = int(tx.get("utime", 0))
            if now_ts < created_at:
                continue
            in_msg = tx.get("in_msg") or {}
            if str(in_msg.get("destination", {}).get("address", "")).lower() not in {"", address.lower()}:
                continue
            amount = Decimal(str(in_msg.get("value", 0))) / Decimal("1000000000")
            if amount >= expected:
                return {"found": True, "txid": tx.get("hash"), "amount": float(amount), "raw": tx}

    if asset == "ETH":
        api_key = os.getenv("ETHERSCAN_API_KEY", "")
        url = (
            "https://api.etherscan.io/api?module=account&action=txlist"
            f"&address={address}&sort=desc&page=1&offset=25&apikey={api_key}"
        )
        data = http_get_json(url)
        for tx in data.get("result", []):
            if str(tx.get("to", "")).lower() != address.lower():
                continue
            if int(tx.get("timeStamp", 0)) < created_at:
                continue
            amount = Decimal(str(tx.get("value", 0))) / Decimal("1000000000000000000")
            if amount >= expected:
                return {"found": True, "txid": tx.get("hash"), "amount": float(amount), "raw": tx}

    return {"found": False}


def provider_invoice_url(provider):
    return (
        provider.get("mini_app_invoice_url")
        or provider.get("web_app_invoice_url")
        or provider.get("invoice_url")
        or provider.get("bot_invoice_url")
        or provider.get("payment_url")
        or provider.get("pay_url")
        or provider.get("url")
    )


def get_provider_payment_id(provider):
    return str(
        provider.get("invoice_id")
        or provider.get("id")
        or provider.get("payment_id")
        or ""
    )


def credit_deposit(order_id, provider_status, raw_payload, paid_statuses=None):
    paid_statuses = paid_statuses or CRYPTO_PAY_PAID_STATUSES
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
        should_credit = provider_status in paid_statuses and not already_credited
        if should_credit:
            asset = str(deposit["crypto_asset"] or "USDT").upper()
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
                INSERT INTO asset_balances (user_id, asset, balance, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, asset) DO UPDATE SET
                    balance = balance + excluded.balance,
                    updated_at = excluded.updated_at
                """,
                (deposit["user_id"], asset, deposit["nc_amount"], now),
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
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "service": "youwin-crypto-backend",
                    "provider": PAYMENT_PROVIDER,
                    "crypto_pay_base": CRYPTO_PAY_API_BASE,
                    "providers": sorted(SUPPORTED_PROVIDERS),
                    "telegram_wallet_url": TELEGRAM_WALLET_URL,
                },
            )
            return

        if url.path == "/api/deposit/status":
            deposit_id = params.get("deposit_id", [""])[0]
            with sqlite3.connect(DATABASE_PATH) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT status, credited, nc_amount, crypto_asset, provider FROM deposits WHERE id = ?",
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
                    "crypto_asset": row["crypto_asset"],
                    "provider": row["provider"],
                },
            )
            return

        if url.path == "/api/deposit/direct/check":
            deposit_id = params.get("deposit_id", [""])[0]
            if not deposit_id:
                json_response(self, 400, {"ok": False, "error": "deposit_id_required"})
                return
            try:
                with sqlite3.connect(DATABASE_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    deposit = conn.execute(
                        "SELECT * FROM deposits WHERE id = ? AND provider = 'direct_crypto'",
                        (deposit_id,),
                    ).fetchone()
                if not deposit:
                    json_response(self, 404, {"ok": False, "error": "deposit_not_found"})
                    return
                if bool(deposit["credited"]):
                    json_response(
                        self,
                        200,
                        {
                            "ok": True,
                            "credited": True,
                            "status": deposit["status"],
                            "nc_amount": deposit["nc_amount"],
                            "crypto_asset": deposit["crypto_asset"],
                        },
                    )
                    return
                check = check_direct_payment(deposit)
                if check.get("found"):
                    result = credit_deposit(deposit["order_id"], "paid", check, {"paid"})
                    json_response(
                        self,
                        200,
                        {
                            "ok": True,
                            "credited": True,
                            "crypto_asset": deposit["crypto_asset"],
                            "nc_amount": deposit["nc_amount"],
                            **result,
                        },
                    )
                    return
                json_response(self, 200, {"ok": True, "credited": False, "status": "waiting"})
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/deposit/quick":
            try:
                user_id = str(params.get("user_id", ["guest"])[0]).strip() or "guest"
                usdt_amount = float(params.get("usdt_amount", ["10"])[0])
                crypto_asset = clean_crypto_asset(params.get("crypto_asset", ["USDT"])[0])
                provider_name = clean_provider(params.get("payment_provider", [PAYMENT_PROVIDER])[0])
                if usdt_amount <= 0:
                    raise ValueError("amount_must_be_positive")

                nc_amount = usdt_amount
                order_id = f"YW-{user_id}-{int(time.time())}"
                provider = create_provider_invoice(provider_name, order_id, usdt_amount, crypto_asset)
                invoice_url = provider_invoice_url(provider)
                if not invoice_url:
                    raise RuntimeError(f"provider_invoice_url_missing: {json.dumps(provider, ensure_ascii=False)}")
                provider_payment_id = get_provider_payment_id(provider)
                now = int(time.time())
                with sqlite3.connect(DATABASE_PATH) as conn:
                    conn.execute(
                        """
                        INSERT INTO deposits (
                            order_id, user_id, usdt_amount, nc_amount,
                            crypto_asset, provider, provider_payment_id, invoice_url, raw_provider_json,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            order_id,
                            user_id,
                            usdt_amount,
                            nc_amount,
                            crypto_asset,
                            provider_name,
                            provider_payment_id,
                            invoice_url,
                            json.dumps(provider),
                            now,
                            now,
                        ),
                    )

                redirect_response(self, invoice_url)
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/balance":
            user_id = params.get("user_id", [""])[0]
            crypto_asset = clean_crypto_asset(params.get("asset", ["USDT"])[0])
            if not user_id:
                json_response(self, 400, {"ok": False, "error": "user_id_required"})
                return
            with sqlite3.connect(DATABASE_PATH) as conn:
                row = conn.execute(
                    "SELECT balance FROM asset_balances WHERE user_id = ? AND asset = ?",
                    (user_id, crypto_asset),
                ).fetchone()
            json_response(self, 200, {"ok": True, "asset": crypto_asset, "balance": float(row[0]) if row else 0})
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        raw_body, payload = read_json(self)

        if url.path == "/api/deposit/create":
            try:
                user_id = str(payload.get("user_id", "")).strip()
                usdt_amount = float(payload.get("usdt_amount", 0))
                crypto_asset = clean_crypto_asset(payload.get("crypto_asset"))
                provider_name = clean_provider(payload.get("payment_provider"))
                if not user_id:
                    raise ValueError("user_id_required")
                if usdt_amount <= 0:
                    raise ValueError("amount_must_be_positive")

                nc_amount = usdt_amount
                order_id = f"YW-{user_id}-{int(time.time())}"
                provider = create_provider_invoice(provider_name, order_id, usdt_amount, crypto_asset)
                invoice_url = provider_invoice_url(provider)
                if not invoice_url:
                    raise RuntimeError(f"provider_invoice_url_missing: {json.dumps(provider, ensure_ascii=False)}")
                provider_payment_id = get_provider_payment_id(provider)
                now = int(time.time())
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO deposits (
                            order_id, user_id, usdt_amount, nc_amount,
                            crypto_asset, provider, provider_payment_id, invoice_url, raw_provider_json,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            order_id,
                            user_id,
                            usdt_amount,
                            nc_amount,
                            crypto_asset,
                            provider_name,
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
                        "crypto_asset": crypto_asset,
                        "nc_amount": nc_amount,
                        "provider": provider_name,
                    },
                )
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/deposit/direct/create":
            try:
                user_id = str(payload.get("user_id", "")).strip()
                amount = Decimal(str(payload.get("amount", "0")))
                crypto_asset = clean_crypto_asset(payload.get("crypto_asset"))
                network = clean_direct_network(crypto_asset, payload.get("network"))
                if not user_id:
                    raise ValueError("user_id_required")
                if amount <= 0:
                    raise ValueError("amount_must_be_positive")
                direct = create_direct_crypto_payment(user_id, amount, crypto_asset, network)
                json_response(self, 200, {"ok": True, **direct})
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/deposit/register-cryptopay":
            try:
                user_id = str(payload.get("user_id", "")).strip()
                order_id = str(payload.get("order_id", "")).strip()
                invoice_url = str(payload.get("invoice_url", "")).strip()
                provider_payment_id = str(payload.get("provider_payment_id", "")).strip()
                usdt_amount = float(payload.get("usdt_amount", 0))
                if not user_id:
                    raise ValueError("user_id_required")
                if not order_id:
                    raise ValueError("order_id_required")
                if not invoice_url:
                    raise ValueError("invoice_url_required")
                if usdt_amount <= 0:
                    raise ValueError("amount_must_be_positive")

                crypto_asset = clean_crypto_asset(payload.get("crypto_asset"))
                nc_amount = usdt_amount
                now = int(time.time())
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO deposits (
                            order_id, user_id, usdt_amount, nc_amount,
                            crypto_asset, provider, provider_payment_id, invoice_url, raw_provider_json,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(order_id) DO UPDATE SET
                            invoice_url = excluded.invoice_url,
                            provider_payment_id = excluded.provider_payment_id,
                            crypto_asset = excluded.crypto_asset,
                            provider = excluded.provider,
                            raw_provider_json = excluded.raw_provider_json,
                            updated_at = excluded.updated_at
                        """,
                        (
                            order_id,
                            user_id,
                            usdt_amount,
                            nc_amount,
                            crypto_asset,
                            "cryptopay",
                            provider_payment_id,
                            invoice_url,
                            json.dumps(payload),
                            now,
                            now,
                        ),
                    )
                    row = conn.execute(
                        "SELECT id FROM deposits WHERE order_id = ?",
                        (order_id,),
                    ).fetchone()
                    deposit_id = row[0] if row else cursor.lastrowid

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
                        "crypto_asset": crypto_asset,
                        "provider": "cryptopay",
                    },
                )
            except Exception as error:
                json_response(self, 400, {"ok": False, "error": str(error)})
            return

        if url.path == "/api/deposit/webhook/cryptopay":
            signature = self.headers.get("crypto-pay-api-signature", "")
            if not verify_crypto_pay_signature(raw_body, signature):
                json_response(self, 401, {"ok": False, "error": "bad_signature"})
                return

            invoice = payload.get("payload") if payload.get("update_type") == "invoice_paid" else payload
            if not isinstance(invoice, dict):
                invoice = payload
            order_id = str(invoice.get("payload", ""))
            status = str(invoice.get("status", "")).lower()
            result = credit_deposit(order_id, status, payload, CRYPTO_PAY_PAID_STATUSES)
            json_response(self, 200, {"ok": True, **result})
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


def main():
    setup_database()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"YouWin crypto backend running on http://{HOST}:{PORT}")
    print("Provider:", PAYMENT_PROVIDER)
    print("Crypto Pay webhook URL:", f"{BACKEND_PUBLIC_URL}/api/deposit/webhook/cryptopay")
    server.serve_forever()


if __name__ == "__main__":
    main()
