from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import uuid
import time
import hmac
import hashlib
import requests

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY_FAM_DEVELOPERS"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USERS_FILE = os.path.join(BASE_DIR, "user_signup.json")
ORDERS_FILE = os.path.join(BASE_DIR, "orders.json")
SERVICES_FILE = os.path.join(BASE_DIR, "services_config.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now()


def read_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data
    except Exception:
        return default


def write_json(path, data):
    temp_path = path + ".tmp"

    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

    os.replace(temp_path, path)


def load_users():
    data = read_json(USERS_FILE, [])
    return data if isinstance(data, list) else []


def save_users(users):
    write_json(USERS_FILE, users)


def load_orders():
    data = read_json(ORDERS_FILE, [])
    return data if isinstance(data, list) else []


def save_orders(orders):
    write_json(ORDERS_FILE, orders)


def load_services():
    data = read_json(SERVICES_FILE, [])
    return data if isinstance(data, list) else []


def load_config():
    data = read_json(CONFIG_FILE, {})
    return data if isinstance(data, dict) else {}


def current_user():
    email = session.get("email")

    if not email:
        return None

    users = load_users()

    for user in users:
        if user.get("email") == email:
            return user

    return None


def update_user(updated_user):
    users = load_users()

    for index, user in enumerate(users):
        if user.get("email") == updated_user.get("email"):
            users[index] = updated_user
            save_users(users)
            return True

    return False


def get_service(service_key):
    services = load_services()

    for service in services:
        if service.get("key") == service_key and service.get("active"):
            return service

    return None


def calculate_amount(service, quantity):
    price_per_100 = float(service.get("price_per_100", 0))
    amount = (quantity / 100) * price_per_100
    return round(amount, 2)


def post_json(url, payload, timeout=45):
    headers_json = {
        "User-Agent": "Mozilla/5.0 (compatible; InstaBooster/1.0)",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    headers_form = {
        "User-Agent": "Mozilla/5.0 (compatible; InstaBooster/1.0)",
        "Accept": "application/json,*/*"
    }

    def parse_response(response):
        raw_response = response.text or ""

        try:
            data = response.json()
            return {
                "success": True,
                "http_code": response.status_code,
                "data": data,
                "raw": raw_response[:5000]
            }
        except Exception:
            lower_raw = raw_response.lower()

            error = "API returned non-JSON response"

            if raw_response.strip() == "":
                error = "API returned empty response"
            elif "cloudflare" in lower_raw or "sorry, you have been blocked" in lower_raw:
                error = "API returned security page instead of JSON"
            elif "<html" in lower_raw:
                error = "API returned HTML page instead of JSON"

            return {
                "success": False,
                "http_code": response.status_code,
                "error": error,
                "raw": raw_response[:5000]
            }

    try:
        # First try JSON body because Volzix docs use JSON body.
        response = requests.post(
            url,
            json=payload,
            headers=headers_json,
            timeout=timeout
        )

        result = parse_response(response)

        # If Volzix complains about JSON body, try form fallback.
        data = result.get("data", {})
        error_text = ""
        if isinstance(data, dict):
            error_text = str(data.get("error", "")) + " " + str(data.get("message", ""))

        raw_text = str(result.get("raw", ""))

        should_fallback = (
            "invalid json body" in error_text.lower()
            or "merchant_mid" in error_text.lower()
            or "required" in error_text.lower()
            or "non-json" in str(result.get("error", "")).lower()
            or "<html" in raw_text.lower()
        )

        if should_fallback:
            response2 = requests.post(
                url,
                data=payload,
                headers=headers_form,
                timeout=timeout
            )
            result2 = parse_response(response2)

            # Keep both responses for debugging but return fallback if it is better.
            if result2.get("success"):
                result2["fallback_used"] = "form"
                result2["json_attempt"] = result
                return result2

            result["fallback_attempt"] = result2

        return result

    except Exception as error:
        return {
            "success": False,
            "http_code": 0,
            "error": str(error),
            "raw": ""
        }


def post_form(url, payload, timeout=45):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; InstaBooster/1.0)",
        "Accept": "application/json,*/*"
    }

    try:
        response = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=timeout
        )

        raw_response = response.text or ""

        try:
            data = response.json()

            return {
                "success": True,
                "http_code": response.status_code,
                "data": data,
                "raw": raw_response[:5000]
            }

        except Exception:
            lower_raw = raw_response.lower()

            error = "API returned non-JSON response"

            if raw_response.strip() == "":
                error = "API returned empty response"
            elif "cloudflare" in lower_raw or "sorry, you have been blocked" in lower_raw:
                error = "Cloudflare blocked this VPS IP. Allow/Skip WAF for 72.61.123.119 on /api/v2."
            elif "<html" in lower_raw:
                error = "API returned HTML page instead of JSON"

            return {
                "success": False,
                "http_code": response.status_code,
                "error": error,
                "raw": raw_response[:5000]
            }

    except Exception as error:
        return {
            "success": False,
            "http_code": 0,
            "error": str(error),
            "raw": ""
        }


def smm_place_order(service_id, link, quantity, comments=""):
    config = load_config()

    api_url = config.get("smm_api_url", "").strip()
    api_key = config.get("smm_api_key", "").strip()

    payload = {
        "key": api_key,
        "action": "add",
        "service": service_id,
        "link": link,
        "quantity": quantity
    }

    if comments:
        payload["comments"] = comments

    result = post_form(api_url, payload)

    if not result.get("success"):
        return {
            "success": False,
            "error": result.get("error"),
            "http_code": result.get("http_code"),
            "raw": result.get("raw")
        }

    data = result.get("data", {})

    if "order" in data:
        return {
            "success": True,
            "smm_order_id": data.get("order"),
            "response": data
        }

    return {
        "success": False,
        "error": data.get("error", "SMM order failed"),
        "response": data,
        "raw": result.get("raw")
    }


def make_signature(sign_string, secret_key):
    return hmac.new(
        secret_key.encode("utf-8"),
        sign_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def volzix_create_payment(amount, web_id, payer_email):
    config = load_config()

    base_url = config.get("volzix_base_url", "https://volzix.com").rstrip("/")
    merchant_mid = config.get("volzix_mid", "").strip()
    merchant_api_key = config.get("volzix_api_key", "").strip()
    return_url = config.get("return_url", "")

    timestamp = int(time.time())
    amount_str = f"{float(amount):.2f}"
    currency = "PKR"

    sign_string = f"{merchant_mid}|{amount_str}|{currency}|{web_id}|{payer_email}|{timestamp}"
    signature = make_signature(sign_string, merchant_api_key)

    payload = {
        "merchant_mid": merchant_mid,
        "amount": float(amount_str),
        "currency": currency,
        "payer_email": payer_email,
        "web_id": web_id,
        "return": return_url,
        "timestamp": timestamp,
        "signature": signature
    }

    result = post_json(f"{base_url}/auth/", payload)

    if not result.get("success"):
        return result

    data = result.get("data", {})
    http_code = result.get("http_code")

    if http_code == 201 and data.get("flow_id"):
        return {
            "success": True,
            "flow_id": data.get("flow_id"),
            "payment_url": data.get("payment_url"),
            "web_id": data.get("web_id"),
            "http_code": http_code,
            "response": data
        }

    return {
        "success": False,
        "error": data.get("error", "Create payment failed"),
        "http_code": http_code,
        "response": data,
        "raw": result.get("raw")
    }


def volzix_charge_wallet(flow_id, mobile_number, gateway):
    config = load_config()

    base_url = config.get("volzix_base_url", "https://volzix.com").rstrip("/")
    merchant_mid = config.get("volzix_mid", "").strip()
    merchant_api_key = config.get("volzix_api_key", "").strip()

    if gateway == "jazzcash":
        endpoint = "/auth/jazzcash-charge/"
    else:
        endpoint = "/auth/easypaisa-charge/"

    timestamp = int(time.time())

    sign_string = f"{merchant_mid}|{flow_id}|{mobile_number}|{timestamp}"
    signature = make_signature(sign_string, merchant_api_key)

    payload = {
        "merchant_mid": merchant_mid,
        "flow_id": flow_id,
        "mobile_number": mobile_number,
        "timestamp": timestamp,
        "signature": signature
    }

    result = post_json(f"{base_url}{endpoint}", payload)

    if not result.get("success"):
        return result

    data = result.get("data", {})
    http_code = result.get("http_code")

    return {
        "success": http_code in [200, 202],
        "http_code": http_code,
        "status": data.get("status"),
        "response": data,
        "raw": result.get("raw"),
        "error": data.get("error") or data.get("message")
    }


def volzix_inquire(flow_id):
    config = load_config()

    base_url = config.get("volzix_base_url", "https://volzix.com").rstrip("/")
    merchant_mid = config.get("volzix_mid", "").strip()
    merchant_api_key = config.get("volzix_api_key", "").strip()

    timestamp = int(time.time())

    sign_string = f"{merchant_mid}|{flow_id}|{timestamp}"
    signature = make_signature(sign_string, merchant_api_key)

    payload = {
        "merchant_mid": merchant_mid,
        "flow_id": flow_id,
        "timestamp": timestamp,
        "signature": signature
    }

    result = post_json(f"{base_url}/inquire/v1/", payload)

    if not result.get("success"):
        return result

    data = result.get("data", {})
    payment = data.get("payment", {})

    return {
        "success": result.get("http_code") == 200,
        "http_code": result.get("http_code"),
        "status": payment.get("status"),
        "status_code": payment.get("status_code"),
        "response": data,
        "raw": result.get("raw"),
        "error": data.get("error")
    }


def create_order_record(user_email, service, link, quantity, order_type, amount=0, comments="", payment_mobile="", gateway=""):
    orders = load_orders()

    order = {
        "id": str(uuid.uuid4()),
        "user_email": user_email,

        "service_key": service.get("key"),
        "service_title": service.get("title"),
        "service_id": service.get("service_id"),

        "link": link,
        "quantity": quantity,
        "comments": comments,

        "order_type": order_type,
        "amount": amount,

        "payment_gateway": gateway,
        "payment_mobile": payment_mobile,
        "payment_status": "not_required" if order_type == "free" else "pending",

        "order_status": "created",
        "smm_order_id": None,

        "flow_id": None,
        "web_id": None,

        "gateway_response": None,
        "inquiry_response": None,
        "smm_response": None,

        "next_payment_check_at": None,
        "last_payment_check_at": None,

        "created_at": now_str(),
        "updated_at": now_str()
    }

    orders.append(order)
    save_orders(orders)

    return order


def update_order(order_id, changes):
    orders = load_orders()

    for index, order in enumerate(orders):
        if order.get("id") == order_id:
            order.update(changes)
            order["updated_at"] = now_str()
            orders[index] = order
            save_orders(orders)
            return order

    return None


def place_smm_for_order(order):
    if not order:
        return None

    if order.get("order_status") == "placed":
        return order

    result = smm_place_order(
        service_id=order.get("service_id"),
        link=order.get("link"),
        quantity=order.get("quantity"),
        comments=order.get("comments", "")
    )

    if result.get("success"):
        return update_order(order.get("id"), {
            "order_status": "placed",
            "smm_order_id": result.get("smm_order_id"),
            "smm_response": result
        })

    return update_order(order.get("id"), {
        "order_status": "failed",
        "smm_response": result
    })


def check_and_fulfill_order(order):
    flow_id = order.get("flow_id")

    if not flow_id:
        return order

    inquiry = volzix_inquire(flow_id)

    changes = {
        "last_payment_check_at": now_str(),
        "inquiry_response": inquiry
    }

    if inquiry.get("status") == "completed" or inquiry.get("status_code") == 200:
        changes["payment_status"] = "completed"
        updated_order = update_order(order.get("id"), changes)
        return place_smm_for_order(updated_order)

    status = inquiry.get("status") or "processing"
    changes["payment_status"] = status

    if status in ["failed", "expired", "cancelled", "dropped", "refunded"]:
        changes["order_status"] = "payment_failed"

    return update_order(order.get("id"), changes)


def auto_check_due_payments():
    config = load_config()
    minutes = int(config.get("payment_check_after_minutes", 10))

    orders = load_orders()

    checked = 0
    fulfilled = 0
    errors = 0

    for order in orders:
        if order.get("order_type") != "paid":
            continue

        if order.get("order_status") == "placed":
            continue

        if not order.get("flow_id"):
            continue

        if order.get("payment_status") not in ["pending", "processing"]:
            continue

        next_check_at = order.get("next_payment_check_at")

        if next_check_at:
            due_time = parse_dt(next_check_at)
        else:
            due_time = parse_dt(order.get("created_at")) + timedelta(minutes=minutes)

        if datetime.now() < due_time:
            continue

        checked += 1

        try:
            before_status = order.get("order_status")
            updated_order = check_and_fulfill_order(order)

            if updated_order and updated_order.get("order_status") == "placed" and before_status != "placed":
                fulfilled += 1

        except Exception:
            errors += 1

    return {
        "checked": checked,
        "fulfilled": fulfilled,
        "errors": errors
    }



def user_public_error():
    return "We could not process your request right now. Please try again later."


def normalize_link(link):
    return (link or "").strip().rstrip("/")


def free_view_allowed_for_link(link):
    target_link = normalize_link(link)
    if not target_link:
        return False

    now_time = datetime.now()

    for order in load_orders():
        if order.get("service_key") != "views":
            continue

        if order.get("order_type") != "free":
            continue

        if normalize_link(order.get("link")) != target_link:
            continue

        created_at = parse_dt(order.get("created_at"))
        diff_minutes = (now_time - created_at).total_seconds() / 60

        if diff_minutes < 60:
            return False

    return True


STYLE = """
<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: Inter, Arial, sans-serif;
  }

  body {
    min-height: 100vh;
    background:
      radial-gradient(circle at top left, rgba(59,130,246,.35), transparent 35%),
      linear-gradient(135deg, #020617, #0f172a 55%, #1e3a8a);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 22px;
    color: #0f172a;
  }

  .box {
    width: 100%;
    max-width: 470px;
    background: rgba(255,255,255,.98);
    padding: 36px;
    border-radius: 26px;
    box-shadow: 0 28px 80px rgba(0,0,0,.35);
    text-align: center;
    border: 1px solid rgba(255,255,255,.5);
  }

  .wide {
    max-width: 1200px;
    text-align: left;
  }

  .brand {
    margin-bottom: 26px;
    text-align: center;
  }

  .brand-badge {
    display: inline-block;
    background: #dbeafe;
    color: #1d4ed8;
    padding: 7px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 900;
    margin-bottom: 12px;
  }

  .brand h1 {
    font-size: 30px;
    margin-bottom: 8px;
    letter-spacing: -0.6px;
    color: #0f172a;
  }

  .brand p {
    color: #64748b;
    font-size: 14px;
    line-height: 1.55;
    margin-bottom: 0;
  }

  h1 {
    font-size: 30px;
    margin-bottom: 8px;
    letter-spacing: -0.5px;
  }

  h2 {
    font-size: 22px;
    margin-bottom: 8px;
  }

  h3 {
    color: #0f172a;
  }

  p {
    color: #64748b;
    font-size: 14px;
    line-height: 1.55;
    margin-bottom: 16px;
  }

  .input-group {
    text-align: left;
    margin-bottom: 16px;
  }

  label {
    display: block;
    color: #334155;
    font-size: 14px;
    margin-bottom: 7px;
    font-weight: 700;
  }

  input,
  textarea,
  select {
    width: 100%;
    padding: 14px 15px;
    border: 1px solid #cbd5e1;
    border-radius: 14px;
    font-size: 15px;
    outline: none;
    background: #fff;
  }

  textarea {
    min-height: 100px;
    resize: vertical;
  }

  input:focus,
  textarea:focus,
  select:focus {
    border-color: #2563eb;
    box-shadow: 0 0 0 4px rgba(37,99,235,.15);
  }

  button,
  .btn {
    display: inline-block;
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 14px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    color: #fff;
    font-size: 16px;
    font-weight: 800;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
    margin-top: 8px;
    box-shadow: 0 10px 25px rgba(37,99,235,.25);
  }

  button:hover,
  .btn:hover {
    filter: brightness(.95);
  }

  .btn-small {
    width: auto;
    padding: 10px 14px;
    font-size: 14px;
    margin: 4px;
  }

  .btn-light {
    background: #f1f5f9;
    color: #0f172a;
    box-shadow: none;
  }

  .links {
    margin-top: 18px;
    font-size: 14px;
    color: #475569;
    text-align: center;
  }

  .links a {
    color: #2563eb;
    text-decoration: none;
    font-weight: 800;
  }

  .footer {
    margin-top: 26px;
    padding-top: 18px;
    border-top: 1px solid #e2e8f0;
    color: #64748b;
    font-size: 13px;
    text-align: center;
  }

  .footer strong {
    color: #0f172a;
  }

  .message {
    margin-bottom: 18px;
    font-size: 14px;
    font-weight: 700;
    color: #166534;
    background: #dcfce7;
    padding: 12px;
    border-radius: 14px;
    text-align: center;
  }

  .warning {
    color: #92400e;
    background: #fef3c7;
  }

  .error {
    color: #991b1b;
    background: #fee2e2;
  }

  .topbar {
    display: flex;
    justify-content: space-between;
    gap: 14px;
    align-items: center;
    margin-bottom: 22px;
    flex-wrap: wrap;
  }

  .hero {
    background: linear-gradient(135deg, #eff6ff, #ffffff);
    border: 1px solid #dbeafe;
    border-radius: 22px;
    padding: 22px;
    margin-bottom: 20px;
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 18px;
    margin-top: 18px;
  }

  .card {
    border: 1px solid #e2e8f0;
    border-radius: 22px;
    padding: 22px;
    background: #fff;
    box-shadow: 0 12px 30px rgba(15,23,42,.08);
  }

  .icon {
    font-size: 34px;
    margin-bottom: 10px;
  }

  .card h3 {
    margin-bottom: 8px;
    font-size: 20px;
  }

  .badge {
    display: inline-block;
    background: #dbeafe;
    color: #1d4ed8;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 800;
    margin-bottom: 12px;
  }

  .muted {
    color: #64748b;
    font-size: 13px;
  }

  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin-top: 20px;
    background: #fff;
    border-radius: 18px;
    overflow: hidden;
  }

  th,
  td {
    padding: 13px;
    border-bottom: 1px solid #e2e8f0;
    text-align: left;
    font-size: 14px;
    vertical-align: top;
  }

  th {
    background: #1e3a8a;
    color: #fff;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .status {
    font-weight: 800;
    text-transform: capitalize;
  }

  @media(max-width: 700px) {
    .box {
      padding: 24px;
    }

    .topbar {
      display: block;
    }

    .btn-small {
      width: 100%;
    }
  }

  @media(max-width: 700px) {
    body {
      padding: 12px;
      align-items: flex-start;
    }

    .wide {
      width: 100%;
      max-width: 100%;
      padding: 20px;
      border-radius: 22px;
    }

    .cards {
      grid-template-columns: 1fr;
      gap: 14px;
    }

    .card {
      padding: 18px;
      border-radius: 20px;
    }

    table {
      display: block;
      overflow-x: auto;
      white-space: nowrap;
      border-radius: 16px;
    }

    th, td {
      font-size: 13px;
      padding: 10px;
    }
  }


  .hamburger {
    display: none;
    width: 44px;
    height: 44px;
    border: 0;
    border-radius: 14px;
    background: rgba(255,255,255,.13);
    color: #ffffff;
    font-size: 24px;
    line-height: 1;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    margin: 0;
    box-shadow: none;
  }

  .mobile-menu {
    display: none;
  }

  @media(max-width: 760px) {
    .desktop-actions {
      display: none !important;
    }

    .hamburger {
      display: inline-flex;
    }

    .mobile-menu {
      display: none;
      width: 100%;
      margin-top: 12px;
      padding: 12px;
      border-radius: 18px;
      background: rgba(255,255,255,.12);
      border: 1px solid rgba(255,255,255,.18);
      backdrop-filter: blur(12px);
    }

    .mobile-menu.open {
      display: grid;
      gap: 10px;
    }

    .mobile-menu a {
      display: block;
      width: 100%;
      padding: 12px 14px;
      border-radius: 14px;
      text-align: center;
      text-decoration: none;
      color: #ffffff;
      font-weight: 900;
      background: rgba(255,255,255,.12);
    }

    .mobile-menu a.primary {
      background: linear-gradient(135deg, #2563eb, #ec4899);
    }

    .topbar {
      align-items: flex-start;
    }

    .topbar-menu-wrap {
      width: 100%;
      display: flex;
      justify-content: flex-end;
      flex-wrap: wrap;
    }

    .dashboard-mobile-menu {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
    }

    .dashboard-mobile-menu a {
      color: #0f172a;
      background: #ffffff;
      border: 1px solid #e2e8f0;
    }

    .dashboard-mobile-menu a.primary {
      color: #ffffff;
      border: none;
    }
  }


  .dashboard-shell {
    width: min(1200px, 94%);
    margin: 0 auto;
  }

  .dashboard-hero-card {
    margin-top: 34px;
    background:
      radial-gradient(circle at 20% 20%, rgba(37,99,235,.16), transparent 32%),
      linear-gradient(135deg, #ffffff, #eff6ff);
    border: 1px solid #dbeafe;
    border-radius: 28px;
    padding: 28px;
    box-shadow: 0 16px 40px rgba(15,23,42,.08);
  }

  .dashboard-hero-card h2 {
    font-size: 30px;
    letter-spacing: -0.8px;
    color: #0f172a;
  }

  .dashboard-hero-card p {
    max-width: 720px;
  }

  .dashboard-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin-top: 18px;
  }

  .dash-stat {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 20px;
    padding: 16px;
  }

  .dash-stat strong {
    display: block;
    font-size: 22px;
    color: #1d4ed8;
    margin-bottom: 4px;
  }

  .dash-stat span {
    color: #64748b;
    font-size: 13px;
    font-weight: 700;
  }

  .services-title {
    margin-top: 28px;
    margin-bottom: 4px;
  }

  .services-title h2 {
    color: #0f172a;
  }

  @media(max-width: 760px) {
    .dashboard-shell {
      width: 100%;
    }

    .dashboard-hero-card {
      margin-top: 26px;
      padding: 20px;
      border-radius: 22px;
    }

    .dashboard-hero-card h2 {
      font-size: 24px;
    }

    .dashboard-stats {
      grid-template-columns: 1fr;
    }

    .topbar h1 {
      font-size: 24px;
      line-height: 1.15;
    }
  }


  .page-header-menu {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
    margin-bottom: 20px;
  }

  .page-header-menu h1 {
    margin: 0;
  }

  .page-menu-wrap {
    display: flex;
    justify-content: flex-end;
    flex-wrap: wrap;
  }

  @media(max-width: 760px) {
    .page-header-menu {
      align-items: flex-start;
    }
  }


  .quantity-buttons {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-top: 10px;
  }

  .qty-btn {
    border: 1px solid #cbd5e1;
    background: #ffffff;
    color: #0f172a;
    padding: 12px 8px;
    border-radius: 14px;
    font-size: 14px;
    font-weight: 900;
    cursor: pointer;
    box-shadow: none;
    margin: 0;
  }

  .qty-btn:hover {
    background: #eff6ff;
    border-color: #2563eb;
  }

  .qty-btn.active {
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    color: #ffffff;
    border-color: transparent;
  }

  @media(max-width: 520px) {
    .quantity-buttons {
      grid-template-columns: repeat(2, 1fr);
    }
  }

</style>
"""


BRAND_HTML = """
<div class="brand">
  <div class="brand-badge">InstaBooster Tool</div>
  <h1>Boost your Instagram</h1>
  <p>Boost your Instagram with InstaBooster Tool by <strong>FAM Developers</strong></p>
</div>
"""


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Login - InstaBooster</title>
  """ + STYLE + """
</head>
<body>
  <div class="box">
    """ + BRAND_HTML + """

    {% if message %}
      <div class="message {{ error_class }}">{{ message }}</div>
    {% endif %}

    <form method="POST" action="/login">
<div class="input-group">
        <label>Email Address</label>
        <input type="email" name="email" placeholder="Enter your email" required>
      </div>

      <div class="input-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your password" required>
      </div>

      <button type="submit">Login</button>
    </form>

    <div class="links">
      Do not have an account?
      <a href="/signup">Sign Up</a>
    </div>

    <div class="footer">
      Project by <strong>FAM Developers</strong>
    </div>
  </div>

<script>
  function toggleMenu(id) {
    var menu = document.getElementById(id);
    if (menu) {
      menu.classList.toggle("open");
    }
  }
</script>

</body>
</html>
"""


SIGNUP_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Signup - InstaBooster</title>
  """ + STYLE + """
</head>
<body>
  <div class="box">
    """ + BRAND_HTML + """

    {% if message %}
      <div class="message {{ error_class }}">{{ message }}</div>
    {% endif %}

    <form method="POST" action="/signup">
      <div class="input-group">
        <label>Full Name</label>
        <input type="text" name="name" placeholder="Enter your full name" required>
      </div>

      <div class="input-group">
        <label>Email Address</label>
        <input type="email" name="email" placeholder="Enter your email" required>
      </div>

      <div class="input-group">
        <label>Phone Number</label>
        <input type="text" name="number" placeholder="03001234567" required>
      </div>

      <div class="input-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your password" required>
      </div>

      <div class="input-group">
        <label>Confirm Password</label>
        <input type="password" name="confirm_password" placeholder="Confirm your password" required>
      </div>

      <button type="submit">Create Account</button>
    </form>

    <div class="links">
      Already have an account?
      <a href="/">Login</a>
    </div>

    <div class="footer">
      Project by <strong>FAM Developers</strong>
    </div>
  </div>
</body>
</html>
"""


DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Dashboard - InstaBooster</title>
  """ + STYLE + """
</head>
<body>
  <div class="box wide">
    <div class="topbar">
      <div>
        <h1>Instagram Growth Dashboard</h1>
        <p>Boost your Instagram with InstaBooster Tool by <strong>FAM Developers</strong></p>
      </div>

      <div class="desktop-actions">
        <a class="btn btn-small btn-light" href="/orders">My Orders</a>
        <a class="btn btn-small btn-light" href="/settings">Settings</a>
        <a class="btn btn-small" href="/logout">Logout</a>
      </div>

      <div class="topbar-menu-wrap">
        <button class="hamburger" type="button" onclick="toggleMenu('dashboardMenu')" style="background:#1d4ed8;">☰</button>
        <div class="mobile-menu dashboard-mobile-menu" id="dashboardMenu">
          <a href="/orders">My Orders</a>
          <a href="/settings">Settings</a>
          <a class="primary" href="/logout">Logout</a>
        </div>
      </div>
    </div>

    <div class="hero">
      <h2>Grow Instagram Faster</h2>
      <p>Free Instagram views are available up to 1000 views. Followers and likes are paid services. Paid orders are processed after payment verification.</p>
    </div>

    <div class="cards">
      {% for service in services %}
        <div class="card">
          <div class="icon">{{ service.icon }}</div>

          {% if service.free_enabled %}
            <span class="badge">Free up to {{ service.free_max_quantity }} views</span>
          {% else %}
            <span class="badge">Paid Service</span>
          {% endif %}

          <h3>{{ service.title }}</h3>
          <p>{{ service.description }}</p>
          <p class="muted">Paid price: PKR {{ service.price_per_100 }} per 100</p>
          <a class="btn" href="/order/{{ service.key }}">Order Now</a>
        </div>
      {% endfor %}
    </div>

    <div class="footer">
      Project by <strong>FAM Developers</strong>
    </div>
  </div>

<script>
  function toggleMenu(id) {
    var menu = document.getElementById(id);
    if (menu) {
      menu.classList.toggle("open");
    }
  }
</script>
</body>
</html>
"""


ORDER_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Order - InstaBooster</title>
  """ + STYLE + """
</head>
<body>
  <div class="box">
    <div class="icon">{{ service.icon }}</div>
    <h1>{{ service.title }}</h1>
    <p>{{ service.description }}</p>

    {% if message %}
      <div class="message {{ error_class }}">{{ message }}</div>
    {% endif %}

    <form method="POST" action="/order/{{ service.key }}">
      <div class="input-group">
        <label>Instagram Link</label>
        <input type="url" name="link" placeholder="https://www.instagram.com/p/..." required>
      </div>

      <div class="input-group">
        <label>Select Quantity</label>

        <input
          type="hidden"
          id="quantityInput"
          name="quantity"
          value="{{ default_quantity }}"
          data-price-per-100="{{ service.price_per_100 }}"
          data-free-enabled="{{ '1' if service.free_enabled else '0' }}"
          data-free-max="{{ service.free_max_quantity if service.free_enabled else 0 }}"
          required
        >

        <div class="quantity-buttons">
          <button type="button" class="qty-btn" data-qty="100" onclick="selectQty(100, this)">100</button>
          <button type="button" class="qty-btn" data-qty="500" onclick="selectQty(500, this)">500</button>
          <button type="button" class="qty-btn" data-qty="1000" onclick="selectQty(1000, this)">1000</button>
          <button type="button" class="qty-btn" data-qty="5000" onclick="selectQty(5000, this)">5000</button>
        </div>
        <div class="message warning" id="amountBox" style="margin-top:12px;">
          Selected Quantity: <strong id="selectedQtyText">{{ default_quantity }}</strong><br>
          Amount to Pay: <strong id="amountToPay">PKR 0</strong>
        </div>
      </div>

      {% if service.key == "comments" %}
        <div class="input-group">
          <label>Comments</label>
          <textarea name="comments" placeholder="One comment per line"></textarea>
        </div>
      {% endif %}

      {% if is_free %}
        <div class="message">Free views are available up to 1000 views. Same link can be used once per hour.</div>
      {% else %}
        <div class="input-group">
          <label>Payment Method</label>
          <select name="gateway" required>
            <option value="easypaisa">EasyPaisa</option>
            <option value="jazzcash">JazzCash</option>
          </select>
        </div>

        <div class="input-group">
          <label>Wallet Number</label>
          <input type="text" name="payment_mobile" placeholder="03001234567" required>
        </div>

        <div class="message warning">
          Order will be placed within 10 minutes after payment confirmation.
        </div>
      {% endif %}

      <button type="submit">{{ "Place Free Order" if is_free else "Pay & Start Verification" }}</button>
    </form>

    <div class="links">
      <a href="/dashboard">Back to Dashboard</a>
    </div>

    <div class="footer">
      Project by <strong>FAM Developers</strong>
    </div>
  </div>

<script>
  function calculateAmountText(qty) {
    var input = document.getElementById("quantityInput");
    if (!input) return "PKR 0";

    var pricePer100 = parseFloat(input.getAttribute("data-price-per-100") || "0");
    var freeEnabled = input.getAttribute("data-free-enabled") === "1";
    var freeMax = parseInt(input.getAttribute("data-free-max") || "0");

    qty = parseInt(qty || "0");

    if (freeEnabled && qty <= freeMax) {
      return "Free";
    }

    var amount = (qty / 100) * pricePer100;
    amount = Math.round(amount * 100) / 100;

    return "PKR " + amount;
  }

  function updateAmountToPay() {
    var input = document.getElementById("quantityInput");
    var qtyText = document.getElementById("selectedQtyText");
    var amountText = document.getElementById("amountToPay");

    if (!input || !qtyText || !amountText) return;

    var qty = parseInt(input.value || "0");

    qtyText.innerText = qty;
    amountText.innerText = calculateAmountText(qty);
  }

  function selectQty(qty, btn) {
    var input = document.getElementById("quantityInput");
    if (!input) return;

    input.value = qty;

    var buttons = document.querySelectorAll(".qty-btn");
    buttons.forEach(function(item) {
      item.classList.remove("active");
    });

    if (btn) {
      btn.classList.add("active");
    }

    updateAmountToPay();
  }

  document.addEventListener("DOMContentLoaded", function() {
    var input = document.getElementById("quantityInput");
    if (!input) return;

    var currentQty = input.value || "100";

    var found = false;
    document.querySelectorAll(".qty-btn").forEach(function(btn) {
      if (btn.getAttribute("data-qty") === currentQty) {
        btn.classList.add("active");
        found = true;
      }
    });

    if (!found) {
      var firstBtn = document.querySelector(".qty-btn");
      if (firstBtn) {
        selectQty(parseInt(firstBtn.getAttribute("data-qty")), firstBtn);
        return;
      }
    }

    updateAmountToPay();
  });
</script>

</body>
</html>
"""



LANDING_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>InstaBooster Tool</title>
  """ + STYLE + """
  <style>
    body {
      align-items: stretch;
      justify-content: stretch;
      padding: 0;
      overflow-x: hidden;
    }

    .landing {
      width: 100%;
      min-height: 100vh;
      color: #ffffff;
      background:
        radial-gradient(circle at 15% 10%, rgba(37,99,235,.55), transparent 28%),
        radial-gradient(circle at 85% 20%, rgba(236,72,153,.35), transparent 28%),
        radial-gradient(circle at 50% 90%, rgba(14,165,233,.35), transparent 30%),
        linear-gradient(135deg, #020617, #0f172a 55%, #172554);
      position: relative;
      overflow: hidden;
    }

    .landing::before {
      content: "";
      position: absolute;
      width: 480px;
      height: 480px;
      border-radius: 50%;
      background: rgba(255,255,255,.06);
      top: -160px;
      right: -120px;
      filter: blur(2px);
    }

    .landing::after {
      content: "";
      position: absolute;
      width: 360px;
      height: 360px;
      border-radius: 50%;
      background: rgba(37,99,235,.18);
      bottom: -120px;
      left: -90px;
      filter: blur(2px);
    }


    .nav {
      width: min(1180px, 92%);
      margin: 0 auto;
      padding: 24px 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      position: relative;
      z-index: 2;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 900;
      letter-spacing: -.3px;
      font-size: 20px;
      color: #ffffff;
      text-decoration: none;
      flex-shrink: 0;
    }

    .logo-mark {
      width: 42px;
      height: 42px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #2563eb, #ec4899);
      box-shadow: 0 15px 40px rgba(37,99,235,.35);
    }

    .nav-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 10px;
      flex-wrap: nowrap;
    }

    .nav-link-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: auto;
      min-width: 92px;
      padding: 11px 18px;
      border-radius: 999px;
      color: #ffffff;
      text-decoration: none;
      font-size: 14px;
      font-weight: 900;
      line-height: 1;
      margin: 0;
      white-space: nowrap;
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(255,255,255,.12);
      box-shadow: none;
      backdrop-filter: blur(12px);
    }

    .signup-top {
      background: linear-gradient(135deg, #2563eb, #ec4899);
      border: none;
      color: #ffffff !important;
    }

    .login-top {
      color: #ffffff !important;
    }

    @media(max-width: 560px) {
      .nav {
        width: 92%;
        padding: 18px 0;
        align-items: center;
        gap: 10px;
      }

      .logo {
        font-size: 16px;
        gap: 8px;
      }

      .logo-mark {
        width: 36px;
        height: 36px;
        border-radius: 12px;
      }

      .nav-actions {
        gap: 7px;
      }

      .nav-link-btn {
        min-width: auto;
        padding: 10px 12px;
        font-size: 12px;
      }
    }

    .hero-wrap {
      width: min(1180px, 92%);
      margin: 0 auto;
      display: grid;
      grid-template-columns: 1.1fr .9fr;
      gap: 34px;
      align-items: center;
      padding: 60px 0 80px;
      position: relative;
      z-index: 2;
    }

    .hero-copy h1 {
      font-size: clamp(42px, 6vw, 76px);
      line-height: .98;
      color: #ffffff;
      letter-spacing: -2.5px;
      margin-bottom: 22px;
    }

    .hero-copy h1 span {
      background: linear-gradient(135deg, #60a5fa, #f472b6, #ffffff);
      -webkit-background-clip: text;
      color: transparent;
    }

    .hero-copy p {
      color: #cbd5e1;
      font-size: 17px;
      max-width: 620px;
      line-height: 1.75;
      margin-bottom: 26px;
    }

    .hero-actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 28px;
    }

    .hero-actions .btn {
      width: auto;
      padding: 14px 22px;
      border-radius: 999px;
      margin: 0;
    }

    .btn-glass {
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: none;
      backdrop-filter: blur(12px);
    }

    .trust-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .trust-pill {
      color: #dbeafe;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.14);
      padding: 9px 12px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 800;
    }

    .phone-card {
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.18);
      border-radius: 34px;
      padding: 18px;
      box-shadow: 0 35px 90px rgba(0,0,0,.35);
      backdrop-filter: blur(16px);
      transform: rotate(2deg);
    }

    .phone-inner {
      background: #ffffff;
      border-radius: 26px;
      padding: 22px;
      color: #0f172a;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-bottom: 18px;
    }

    .stat {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 18px;
      padding: 16px;
    }

    .stat strong {
      display: block;
      font-size: 25px;
      color: #1d4ed8;
      margin-bottom: 5px;
    }

    .stat span {
      color: #64748b;
      font-size: 13px;
      font-weight: 700;
    }

    .mini-service {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px;
      border-radius: 18px;
      background: linear-gradient(135deg, #eff6ff, #ffffff);
      border: 1px solid #dbeafe;
      margin-top: 12px;
    }

    .mini-service b {
      color: #0f172a;
      font-size: 14px;
    }

    .mini-service small {
      color: #64748b;
      display: block;
      margin-top: 3px;
    }

    .sections {
      width: min(1180px, 92%);
      margin: 0 auto;
      position: relative;
      z-index: 2;
      padding-bottom: 70px;
    }

    .section-title {
      text-align: center;
      margin-bottom: 28px;
    }

    .section-title h2 {
      color: #ffffff;
      font-size: 36px;
      letter-spacing: -1px;
    }

    .section-title p {
      color: #cbd5e1;
      max-width: 680px;
      margin: 10px auto 0;
    }

    .how-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 26px;
    }

    .how-card {
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.15);
      border-radius: 24px;
      padding: 20px;
      color: #ffffff;
      backdrop-filter: blur(14px);
    }

    .step-no {
      width: 38px;
      height: 38px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #2563eb, #ec4899);
      font-weight: 900;
      margin-bottom: 14px;
    }

    .how-card h3 {
      color: #ffffff;
      font-size: 17px;
      margin-bottom: 8px;
    }

    .how-card p {
      color: #cbd5e1;
      font-size: 14px;
      margin: 0;
    }

    .feature-panel {
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.15);
      border-radius: 28px;
      padding: 24px;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      backdrop-filter: blur(14px);
    }

    .feature {
      background: rgba(255,255,255,.08);
      border-radius: 20px;
      padding: 18px;
    }

    .feature h3 {
      color: #ffffff;
      margin-bottom: 8px;
    }

    .feature p {
      color: #cbd5e1;
      margin: 0;
      font-size: 14px;
    }


    .landing-footer {
      width: min(1180px, 92%);
      margin: 0 auto;
      position: relative;
      z-index: 2;
      padding: 28px 0 34px;
      border-top: 1px solid rgba(255,255,255,.14);
      display: grid;
      grid-template-columns: 1.2fr .8fr;
      gap: 20px;
      color: #cbd5e1;
    }

    .landing-footer h3 {
      color: #ffffff;
      font-size: 18px;
      margin-bottom: 10px;
    }

    .landing-footer p {
      color: #cbd5e1;
      margin: 0 0 7px;
      font-size: 14px;
    }

    .developer-list {
      display: grid;
      gap: 8px;
    }

    .developer-name {
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.13);
      border-radius: 14px;
      padding: 10px 12px;
      color: #ffffff;
      font-weight: 800;
    }


    .dashboard-service-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .mobile-note {
      display: none;
    }

    @media(max-width: 900px) {
      .hero-wrap {
        grid-template-columns: 1fr;
        padding-top: 38px;
      }

      .phone-card {
        transform: none;
      }

      .how-grid,
      .feature-panel,
      .landing-footer {
        grid-template-columns: 1fr;
      }

      .nav-actions .hero-copy h1 {
        font-size: 42px;
        letter-spacing: -1.5px;
      }

      .trust-row {
        gap: 8px;
      }

      .trust-pill {
        font-size: 12px;
      }

      .mobile-note {
        display: block;
      }
    }
  </style>
</head>
<body>
  <main class="landing">
    <nav class="nav">
      <a href="/" class="logo">
        <span class="logo-mark">⚡</span>
        <span>InstaBooster</span>
      </a>

      <div class="nav-actions desktop-actions">
        <a class="nav-link-btn login-top" href="/login">Login</a>
        <a class="nav-link-btn signup-top" href="/signup">Sign Up</a>
      </div>

      <button class="hamburger" type="button" onclick="toggleMenu('landingMenu')">☰</button>

      <div class="mobile-menu" id="landingMenu">
        <a href="/login">Login</a>
        <a class="primary" href="/signup">Sign Up</a>
      </div>
    </nav>

    <section class="hero-wrap">
      <div class="hero-copy">
        <h1>Boost Instagram with a <span>smart growth tool</span></h1>
        <p>
          InstaBooster Tool by FAM Developers helps users increase Instagram views, likes, and followers through a clean dashboard.
          Users can place orders, verify payment, and track order status from one simple panel.
        </p>

        <div class="hero-actions">
          <a class="btn" href="/login">Login to Dashboard</a>
          <a class="btn btn-glass" href="#how">How It Works</a>
        </div>

        <div class="trust-row">
          <span class="trust-pill">Free Views Trial</span>
          <span class="trust-pill">JazzCash & EasyPaisa</span>
          <span class="trust-pill">Auto Payment Check</span>
          <span class="trust-pill">Order Tracking</span>
        </div>
      </div>

      <div class="phone-card">
        <div class="phone-inner">
          <div class="brand-badge">Live Dashboard Preview</div>
          <h2>Growth Services</h2>
          <p>Select your service, paste Instagram link, choose quantity, and submit order.</p>

          <div class="stats-grid">
            <div class="stat">
              <strong>1000</strong>
              <span>Free Views Limit</span>
            </div>
            <div class="stat">
              <strong>10m</strong>
              <span>Payment Verify</span>
            </div>
          </div>

          <div class="mini-service">
            <div>
              <b>Instagram Views</b>
              <small>Free up to 1000 views</small>
            </div>
            <span>👁️</span>
          </div>

          <div class="mini-service">
            <div>
              <b>Instagram Followers</b>
              <small>Paid premium growth</small>
            </div>
            <span>👥</span>
          </div>

          <div class="mini-service">
            <div>
              <b>Instagram Likes</b>
              <small>Paid engagement boost</small>
            </div>
            <span>❤️</span>
          </div>
        </div>
      </div>
    </section>

    <section class="sections" id="how">
      <div class="section-title">
        <h2>How to use InstaBooster Tool</h2>
        <p>Simple process for users: login, select service, add Instagram link, verify payment if needed, and track the order.</p>
      </div>

      <div class="how-grid">
        <div class="how-card">
          <div class="step-no">1</div>
          <h3>Create Account</h3>
          <p>User signs up with email, phone number, and password. Account data is stored safely in JSON for this project demo.</p>
        </div>

        <div class="how-card">
          <div class="step-no">2</div>
          <h3>Select Service</h3>
          <p>Choose Instagram Views, Likes, or Followers from the dashboard. Views include a free trial limit.</p>
        </div>

        <div class="how-card">
          <div class="step-no">3</div>
          <h3>Submit Link</h3>
          <p>Paste Instagram post/profile link, select quantity, and confirm the order details before placing order.</p>
        </div>

        <div class="how-card">
          <div class="step-no">4</div>
          <h3>Track Order</h3>
          <p>Paid orders are checked after payment confirmation. Order will be placed within 10 minutes after payment confirmation.</p>
        </div>
      </div>

      <div class="feature-panel">
        <div class="feature">
          <h3>Free Views System</h3>
          <p>Users can get free Instagram views up to the configured free limit. Same link can use free views once per hour.</p>
        </div>

        <div class="feature">
          <h3>Paid Growth Services</h3>
          <p>Followers and likes are paid services. Payment is handled through JazzCash or EasyPaisa integration.</p>
        </div>

        <div class="feature">
          <h3>Backend Automation</h3>
          <p>The system checks payment status automatically and places the order after confirmation.</p>
        </div>
      </div>
    </section>

    <footer class="landing-footer">
      <div>
        <h3>Contact Details</h3>
        <p>For project details, support, or demo-related queries, contact our development team.</p>
        <p><strong>Email:</strong> fema.qureshi@gmail.com</p>
        <p><strong>Email:</strong> muhammadbaig720@gmail.com</p>
      </div>

      <div>
        <h3>Our Developers</h3>
        <div class="developer-list">
          <div class="developer-name">Fatima Qureshi</div>
          <div class="developer-name">Maleeha Zulfiqar</div>
          <div class="developer-name">Aima Aqeel</div>
        </div>
      </div>
    </footer>

  </main>

<script>
  function updateCharges() {
    var input = document.getElementById("quantityInput");
    var amountBox = document.getElementById("chargesAmount");
    var chargesBox = document.getElementById("chargesBox");

    if (!input || !amountBox || !chargesBox) return;

    var qty = parseInt(input.value || "0");
    var pricePer100 = parseFloat(input.dataset.pricePer100 || "0");
    var freeEnabled = input.dataset.freeEnabled === "1";
    var freeMax = parseInt(input.dataset.freeMax || "0");

    var chargeableQty = qty;

    if (freeEnabled && qty <= freeMax) {
      amountBox.innerText = "0";
      chargesBox.innerHTML = "Estimated Charges: <strong>Free</strong>";
      return;
    }

    var amount = (chargeableQty / 100) * pricePer100;
    amount = Math.round(amount * 100) / 100;

    amountBox.innerText = amount;
    chargesBox.innerHTML = "Estimated Charges: PKR <strong>" + amount + "</strong>";
  }

  document.addEventListener("DOMContentLoaded", updateCharges);
</script>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(LANDING_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("email"):
            return redirect(url_for("dashboard"))

        return render_template_string(
            LOGIN_PAGE,
            message="",
            error_class=""
        )

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    for user in load_users():
        if user.get("email") == email and check_password_hash(user.get("password", ""), password):
            session["email"] = email
            return redirect(url_for("dashboard"))

    return render_template_string(
        LOGIN_PAGE,
        message="Invalid email or password.",
        error_class="error"
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template_string(
            SIGNUP_PAGE,
            message="",
            error_class=""
        )

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    number = request.form.get("number", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not name or not email or not number or not password or not confirm_password:
        return render_template_string(
            SIGNUP_PAGE,
            message="All fields are required.",
            error_class="error"
        )

    if password != confirm_password:
        return render_template_string(
            SIGNUP_PAGE,
            message="Password and confirm password do not match.",
            error_class="error"
        )

    users = load_users()

    for user in users:
        if user.get("email") == email:
            return render_template_string(
                SIGNUP_PAGE,
                message="This email is already registered.",
                error_class="error"
            )

    users.append({
        "id": len(users) + 1,
        "name": name,
        "email": email,
        "number": number,
        "password": generate_password_hash(password),
        "free_used": {},
        "created_at": now_str()
    })

    save_users(users)

    return redirect(url_for("login_page"))



SETTINGS_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Settings - InstaBooster</title>
  """ + STYLE + """
</head>
<body>
  <div class="box">
    <div class="page-header-menu">
      <div>
        <div class="brand-badge">Account Settings</div>
        <h1>Settings</h1>
      </div>

      <div class="page-menu-wrap">
        <button class="hamburger" type="button" onclick="toggleMenu('settingsMenu')" style="background:#1d4ed8;">☰</button>
        <div class="mobile-menu dashboard-mobile-menu" id="settingsMenu">
          <a href="/dashboard">Dashboard</a>
          <a href="/orders">My Orders</a>
          <a class="primary" href="/logout">Logout</a>
        </div>
      </div>
    </div>

    <p>Update your account email or password securely.</p>

    {% if message %}
      <div class="message {{ error_class }}">{{ message }}</div>
    {% endif %}

    <form method="POST" action="/settings">
      <div class="input-group">
        <label>Full Name</label>
        <input type="text" name="name" value="{{ user.name or '' }}" placeholder="Enter your full name" required>
      </div>

      <div class="input-group">
        <label>Email Address</label>
        <input type="email" name="email" value="{{ user.email }}" placeholder="Enter new email" required>
      </div>

      <div class="input-group">
        <label>Current Password</label>
        <input type="password" name="current_password" placeholder="Enter current password" required>
      </div>

      <div class="input-group">
        <label>New Password</label>
        <input type="password" name="new_password" placeholder="Leave blank if you do not want to change">
      </div>

      <div class="input-group">
        <label>Confirm New Password</label>
        <input type="password" name="confirm_password" placeholder="Confirm new password">
      </div>

      <button type="submit">Save Changes</button>
    </form>

    <div class="links">
      <a href="/dashboard">Back to Dashboard</a>
    </div>

    <div class="footer">
      Project by <strong>FAM Developers</strong>
    </div>
  </div>

<script>
  function toggleMenu(id) {
    var menu = document.getElementById(id);
    if (menu) {
      menu.classList.toggle("open");
    }
  }
</script>
</body>
</html>
"""


@app.route("/settings", methods=["GET", "POST"])
def settings():
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    if request.method == "GET":
        return render_template_string(
            SETTINGS_PAGE,
            user=user,
            message="",
            error_class=""
        )

    name = request.form.get("name", "").strip()
    new_email = request.form.get("email", "").strip()
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not name or not new_email or not current_password:
        return render_template_string(
            SETTINGS_PAGE,
            user=user,
            message="Name, email and current password are required.",
            error_class="error"
        )

    if not check_password_hash(user.get("password", ""), current_password):
        return render_template_string(
            SETTINGS_PAGE,
            user=user,
            message="Current password is incorrect.",
            error_class="error"
        )

    users = load_users()

    for item in users:
        if item.get("email") == new_email and item.get("email") != user.get("email"):
            return render_template_string(
                SETTINGS_PAGE,
                user=user,
                message="This email is already used by another account.",
                error_class="error"
            )

    if new_password:
        if new_password != confirm_password:
            return render_template_string(
                SETTINGS_PAGE,
                user=user,
                message="New password and confirm password do not match.",
                error_class="error"
            )

        user["password"] = generate_password_hash(new_password)

    old_email = user.get("email")
    user["name"] = name
    user["email"] = new_email

    # Update user record
    for index, item in enumerate(users):
        if item.get("email") == old_email:
            users[index] = user
            break

    save_users(users)

    # Update orders owner email if email changed
    if old_email != new_email:
        orders = load_orders()
        for order in orders:
            if order.get("user_email") == old_email:
                order["user_email"] = new_email
        save_orders(orders)
        session["email"] = new_email

    return render_template_string(
        SETTINGS_PAGE,
        user=user,
        message="Account settings updated successfully.",
        error_class=""
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    return render_template_string(
        DASHBOARD_PAGE,
        services=load_services()
    )


@app.route("/order/<service_key>", methods=["GET", "POST"])
def order_page(service_key):
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    service = get_service(service_key)

    if not service:
        return "Service not found", 404

    free_enabled = bool(service.get("free_enabled", False))
    free_max_quantity = int(service.get("free_max_quantity", 0) or 0)

    if request.method == "GET":
        default_quantity = service.get("min_quantity")
        amount = calculate_amount(service, default_quantity)

        is_free = free_enabled

        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=is_free,
            default_quantity=default_quantity,
            amount=amount,
            message="",
            error_class=""
        )

    link = request.form.get("link", "").strip()
    quantity = int(request.form.get("quantity", 0))
    comments = request.form.get("comments", "").strip()
    payment_mobile = request.form.get("payment_mobile", "").strip()
    gateway = request.form.get("gateway", "easypaisa").strip()

    if gateway not in ["easypaisa", "jazzcash"]:
        gateway = "easypaisa"

    if not link or quantity <= 0:
        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=free_enabled,
            default_quantity=quantity,
            amount=calculate_amount(service, quantity),
            message="Invalid order details.",
            error_class="error"
        )

    if quantity < int(service.get("min_quantity")) or quantity > int(service.get("max_quantity")):
        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=free_enabled,
            default_quantity=quantity,
            amount=calculate_amount(service, quantity),
            message="Quantity is out of allowed range.",
            error_class="error"
        )

    # Only views can be free.
    if service_key == "views" and free_enabled and quantity <= free_max_quantity:
        if not free_view_allowed_for_link(link):
            return render_template_string(
                ORDER_PAGE,
                service=service,
                is_free=True,
                default_quantity=quantity,
                amount=calculate_amount(service, quantity),
                message="This link already received free views recently. Please try again after 1 hour or place a paid order above 1000 views.",
                error_class="error"
            )

        new_order = create_order_record(
            user_email=user.get("email"),
            service=service,
            link=link,
            quantity=quantity,
            order_type="free",
            amount=0,
            comments=comments
        )

        placed_order = place_smm_for_order(new_order)

        if placed_order and placed_order.get("order_status") == "placed":
            return redirect(url_for("orders_page"))

        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=True,
            default_quantity=quantity,
            amount=calculate_amount(service, quantity),
            message=user_public_error(),
            error_class="error"
        )

    # Paid order flow for followers, likes, and views above 1000.
    amount = calculate_amount(service, quantity)

    if not payment_mobile:
        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=False,
            default_quantity=quantity,
            amount=amount,
            message="Wallet number is required.",
            error_class="error"
        )

    new_order = create_order_record(
        user_email=user.get("email"),
        service=service,
        link=link,
        quantity=quantity,
        order_type="paid",
        amount=amount,
        comments=comments,
        payment_mobile=payment_mobile,
        gateway=gateway
    )

    web_id = "ORDER-" + datetime.now().strftime("%Y%m%d%H%M%S") + "-" + new_order.get("id")[:8]

    payment = volzix_create_payment(
        amount=amount,
        web_id=web_id,
        payer_email=user.get("email")
    )

    if not payment.get("success"):
        update_order(new_order.get("id"), {
            "payment_status": "failed",
            "web_id": web_id,
            "gateway_response": payment
        })

        return render_template_string(
            ORDER_PAGE,
            service=service,
            is_free=False,
            default_quantity=quantity,
            amount=amount,
            message="Payment could not be started. Please try again later.",
            error_class="error"
        )

    flow_id = payment.get("flow_id")

    check_minutes = int(load_config().get("payment_check_after_minutes", 10))
    next_check_at = (datetime.now() + timedelta(minutes=check_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    update_order(new_order.get("id"), {
        "web_id": web_id,
        "flow_id": flow_id,
        "next_payment_check_at": next_check_at,
        "gateway_response": {
            "create_payment": payment
        }
    })

    charge = volzix_charge_wallet(
        flow_id=flow_id,
        mobile_number=payment_mobile,
        gateway=gateway
    )

    payment_status = charge.get("status") or "processing"

    update_order(new_order.get("id"), {
        "payment_status": payment_status,
        "gateway_response": {
            "create_payment": payment,
            "charge": charge
        }
    })

    if charge.get("http_code") == 200 and charge.get("status") == "completed":
        updated = update_order(new_order.get("id"), {
            "payment_status": "completed"
        })

        place_smm_for_order(updated)

        return redirect(url_for("orders_page"))

    # Even if gateway gives unusual response, show pending message and save backend response.
    return redirect(url_for("payment_pending", order_id=new_order.get("id")))


@app.route("/payment/pending/<order_id>")
def payment_pending(order_id):
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    orders = load_orders()

    order = next(
        (
            item for item in orders
            if item.get("id") == order_id and item.get("user_email") == user.get("email")
        ),
        None
    )

    if not order:
        return "Order not found", 404

    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1.0">
      <title>Payment Pending - InstaBooster</title>
      """ + STYLE + """
    </head>
    <body>
      <div class="box">
        <div class="brand-badge">Payment Verification</div>
        <h1>Payment Processing</h1>

        <p>Please check your {{ order.payment_gateway|capitalize }} wallet/app and confirm payment.</p>

        <div class="message warning">
          Order will be placed within 10 minutes after payment confirmation.
        </div>

        <p><strong>Amount:</strong> PKR {{ order.amount }}</p>
        <p><strong>Service:</strong> {{ order.service_title }}</p>
        <p><strong>Next Auto Check:</strong> {{ order.next_payment_check_at }}</p>

        <a class="btn" href="/payment/check/{{ order.id }}">Check Payment Now</a>

        <div class="links">
          <a href="/orders">My Orders</a>
        </div>

        <div class="footer">
          Project by <strong>FAM Developers</strong>
        </div>
      </div>
    </body>
    </html>
    """

    return render_template_string(
        html,
        order=order
    )


@app.route("/payment/check/<order_id>")
def payment_check(order_id):
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    orders = load_orders()

    order = next(
        (
            item for item in orders
            if item.get("id") == order_id and item.get("user_email") == user.get("email")
        ),
        None
    )

    if not order:
        return "Order not found", 404

    check_and_fulfill_order(order)

    return redirect(url_for("orders_page"))


@app.route("/orders")
def orders_page():
    user = current_user()

    if not user:
        return redirect(url_for("login_page"))

    orders = [
        order for order in load_orders()
        if order.get("user_email") == user.get("email")
    ]

    orders = list(reversed(orders))

    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1.0">
      <title>Orders - InstaBooster</title>
      """ + STYLE + """
    </head>
    <body>
      <div class="box wide">
        <div class="topbar">
          <div>
            <h1>My Orders</h1>
            <p>Free and paid orders status.</p>
          </div>

          <div class="desktop-actions">
            <a class="btn btn-small btn-light" href="/dashboard">Dashboard</a>
            <a class="btn btn-small btn-light" href="/settings">Settings</a>
            <a class="btn btn-small" href="/logout">Logout</a>
          </div>

          <div class="topbar-menu-wrap">
            <button class="hamburger" type="button" onclick="toggleMenu('ordersMenu')" style="background:#1d4ed8;">☰</button>
            <div class="mobile-menu dashboard-mobile-menu" id="ordersMenu">
              <a href="/dashboard">Dashboard</a>
              <a href="/settings">Settings</a>
              <a class="primary" href="/logout">Logout</a>
            </div>
          </div>
        </div>

        <table>
          <tr>
            <th>Service</th>
            <th>Gateway</th>
            <th>Qty</th>
            <th>Amount</th>
            <th>Payment</th>
            <th>Order</th>
            <th>SMM ID</th>
            <th>Next Check</th>
            <th>Action</th>
          </tr>

          {% for order in orders %}
          <tr>
            <td>
              {{ order.service_title }}
              
            </td>

            <td>{{ order.payment_gateway or "-" }}</td>
            <td>{{ order.quantity }}</td>
            <td>PKR {{ order.amount }}</td>

            <td>
              <span class="status">{{ order.payment_status }}</span>
            </td>

            <td>
              <span class="status">{{ order.order_status }}</span>
            </td>

            <td>{{ order.smm_order_id or "-" }}</td>
            <td>{{ order.next_payment_check_at or "-" }}</td>

            <td>
              {% if order.payment_status in ["processing", "pending"] and order.flow_id %}
                <a href="/payment/check/{{ order.id }}">Check</a>
              {% else %}
                -
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </table>

        <div class="footer">
          Project by <strong>FAM Developers</strong>
        </div>
      </div>
    
<script>
  function toggleMenu(id) {
    var menu = document.getElementById(id);
    if (menu) {
      menu.classList.toggle("open");
    }
  }
</script>
</body>
    </html>
    """

    return render_template_string(
        html,
        orders=orders
    )


@app.route("/payment/return")
def payment_return():
    return redirect(url_for("orders_page"))


@app.route("/cron/check-payments")
def cron_check_payments():
    secret = request.args.get("secret", "")
    config_secret = load_config().get("cron_secret", "")

    if secret != config_secret:
        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    result = auto_check_due_payments()

    return jsonify({
        "success": True,
        "result": result
    })


@app.route("/admin/debug/orders")
def debug_orders():
    return "<pre>" + json.dumps(load_orders(), indent=4, ensure_ascii=False) + "</pre>"


@app.route("/admin/debug/users")
def debug_users():
    users = load_users()

    safe_users = []

    for user in users:
        item = dict(user)
        item["password"] = "***HASHED***"
        safe_users.append(item)

    return "<pre>" + json.dumps(safe_users, indent=4, ensure_ascii=False) + "</pre>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)