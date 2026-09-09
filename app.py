from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time
import logging
import random
from queue import Queue, Empty
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from data_pb2 import AccountPersonalShowInfo
from google.protobuf.descriptor import FieldDescriptor
import uid_generator_pb2
import GetWishListItems_pb2

# ------------------ Logging Setup ------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------ JWT Cache ------------------
jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()

# ------------------ HTTP Session / Rate Limit Queue ------------------
# The upstream API can return HTTP 429 when too many requests arrive too quickly.
# We use a single bounded worker queue so requests are serialized and spaced out,
# while Retry-After/exponential backoff handles transient 429/5xx responses.
REQUEST_QUEUE_SIZE = 50
REQUEST_INTERVAL = 0.75
MAX_RETRIES = 4
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 15

request_queue = Queue(maxsize=REQUEST_QUEUE_SIZE)
last_upstream_request = 0.0
request_pacing_lock = threading.Lock()


def create_http_session():
    session = requests.Session()
    # Do not blindly retry 429 here: the queue worker below handles it so we can
    # respect Retry-After and avoid a retry storm.
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


http_session = create_http_session()


def _pace_upstream_request():
    global last_upstream_request
    with request_pacing_lock:
        now = time.monotonic()
        wait = REQUEST_INTERVAL - (now - last_upstream_request)
        if wait > 0:
            time.sleep(wait)
        last_upstream_request = time.monotonic()


def _retry_after_seconds(response, attempt):
    value = response.headers.get("Retry-After")
    if value:
        try:
            return min(30.0, max(0.0, float(value)))
        except ValueError:
            pass
    # Jitter prevents multiple app threads from retrying simultaneously.
    return min(30.0, (2 ** attempt) + random.uniform(0, 0.5))


class _QueuedRequest:
    __slots__ = ("url", "headers", "data", "timeout", "event", "response", "error")

    def __init__(self, url, headers, data, timeout):
        self.url = url
        self.headers = headers
        self.data = data
        self.timeout = timeout
        self.event = threading.Event()
        self.response = None
        self.error = None


def _worker():
    while True:
        item = request_queue.get()
        try:
            for attempt in range(MAX_RETRIES + 1):
                try:
                    _pace_upstream_request()
                    response = http_session.post(
                        item.url,
                        headers=item.headers,
                        data=item.data,
                        timeout=item.timeout,
                    )
                    if response.status_code != 429:
                        item.response = response
                        break

                    if attempt >= MAX_RETRIES:
                        item.response = response
                        break

                    delay = _retry_after_seconds(response, attempt)
                    logger.warning(
                        "[429] Upstream rate limit for %s; retrying in %.2fs (%d/%d)",
                        item.url, delay, attempt + 1, MAX_RETRIES
                    )
                    time.sleep(delay)
                except requests.RequestException as exc:
                    if attempt >= MAX_RETRIES:
                        item.error = exc
                        break
                    delay = min(15.0, (2 ** attempt) * 0.5 + random.uniform(0, 0.25))
                    logger.warning(
                        "[UPSTREAM] %s; retrying in %.2fs (%d/%d)",
                        exc, delay, attempt + 1, MAX_RETRIES
                    )
                    time.sleep(delay)
        finally:
            item.event.set()
            request_queue.task_done()


worker_thread = threading.Thread(target=_worker, name="upstream-worker", daemon=True)
worker_thread.start()


class UpstreamRateLimitError(Exception):
    def __init__(self, message, status_code=429, retry_after=None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def queued_post(url, headers=None, data=None, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)):
    item = _QueuedRequest(url, headers, data, timeout)
    try:
        request_queue.put_nowait(item)
    except Exception:
        raise UpstreamRateLimitError(
            "Upstream request queue is full. Please try again shortly.", 503, 5
        )

    if not item.event.wait(timeout=READ_TIMEOUT + 40):
        raise UpstreamRateLimitError(
            "Upstream server did not respond in time. Please try again.", 504
        )
    if item.error:
        raise item.error
    if item.response is None:
        raise UpstreamRateLimitError("No response from upstream server.", 502)
    return item.response

# ------------------ Protobuf to Dict ------------------
def proto_to_dict(message):
    """
    Safely converts protobuf to dict without relying on buggy 'label' attributes.
    """
    result = {}
    
    for field in getattr(message.DESCRIPTOR, 'fields', []):
        value = getattr(message, field.name)
        val_type = type(value).__name__
        
        if 'MapContainer' in val_type:
            map_result = {}
            for k, v in value.items():
                if hasattr(v, 'DESCRIPTOR'):
                    map_result[k] = proto_to_dict(v)
                elif isinstance(v, bytes):
                    map_result[k] = binascii.hexlify(v).decode('utf-8')
                else:
                    map_result[k] = v
            result[field.name] = map_result
            
        elif 'Repeated' in val_type:
            list_result = []
            for item in value:
                if hasattr(item, 'DESCRIPTOR'):
                    list_result.append(proto_to_dict(item))
                elif isinstance(item, bytes):
                    list_result.append(binascii.hexlify(item).decode('utf-8'))
                else:
                    list_result.append(item)
            result[field.name] = list_result
            
        elif hasattr(value, 'DESCRIPTOR'):
            result[field.name] = proto_to_dict(value)
            
        elif getattr(field, 'type', None) == 14: # 14 is FieldDescriptor.TYPE_ENUM
            try:
                result[field.name] = field.enum_type.values_by_number[value].name
            except:
                result[field.name] = value
                
        elif isinstance(value, bytes):
            result[field.name] = binascii.hexlify(value).decode('utf-8') if value else ""
            
        else:
            result[field.name] = value

    return result


def extract_token_from_response(data, region):
    """Safely extract JWT token from API response."""
    if not isinstance(data, dict):
        return None
    
    # Try common token keys
    token = data.get("jwt_token") or data.get("token") or data.get("access_token")
    if token:
        return token
    
    # Sometimes nested in 'data'
    if "data" in data and isinstance(data["data"], dict):
        token = data["data"].get("token") or data["data"].get("jwt_token")
        if token:
            return token
    
    # Legacy region-specific checks (kept for compatibility)
    if data.get("success") is True and "token" in data:
        return data["token"]
    
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH"]:
        if 'token' in data:
            return data['token']
    else:
        if data.get('status') == 'success':
            return data.get('token')
    
    return None

def ensure_jwt_token_sync(region):
    """Ensure JWT token is available; fetch/refresh automatically if missing or expired."""
    global jwt_tokens, jwt_expiry
    current_time = time.time()

    # Normalize region: 'DEFAULT' -> use 'default' key
    if region.upper() == "DEFAULT":
        region = "default"

    # If token exists and is valid, return it
    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
        return jwt_tokens[region]

    with jwt_lock:
        # double-check after acquiring lock
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
            return jwt_tokens[region]

        logger.info(f"[JWT] Token missing or expired for {region}. Fetching...")

        endpoints = {
            "IND": "https://jwt-phi-ten.vercel.app/token?uid=6994493475&password=1_JAHID_X_EMPIRE_9r0A2xxT",
            "BR": "https://jwt-phi-ten.vercel.app/token?uid=4345418798&password=JOBAYAR_GK6VJ",
            "US": "https://jwt-phi-ten.vercel.app/token?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
            "SAC": "https://jwt-phi-ten.vercel.app/token?uid=6994520397&password=1_JAHID_X_EMPIRE_quRc2lOr",
            "BD": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "ID": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "PK": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "VN": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "ME": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "TH": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP",
            "default": "https://jwt-phi-ten.vercel.app/token?uid=6994726488&password=1_JAHID_X_EMPIRE_yLAicWRP"
        }

        url = endpoints.get(region, endpoints["default"])

        try:
            response = http_session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "5")
                raise UpstreamRateLimitError("JWT service rate limited", 429, retry_after)
            response.raise_for_status()
            data = response.json()

            token = extract_token_from_response(data, region)
            if token:
                jwt_tokens[region] = token
                jwt_expiry[region] = current_time + 600  # 10 minutes
                logger.info(f"[JWT] Token for {region} updated.")
                return token
            else:
                logger.error(f"[JWT] Failed to extract token for {region}. Response: {data}")

        except Exception as e:
            logger.error(f"[JWT] Request error for {region}: {e}")

    return jwt_tokens.get(region)


def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, region):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        data = bytes.fromhex(idd)
        response = queued_post(endpoint, headers=headers, data=data)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise UpstreamRateLimitError("Free Fire API rate limit reached", 429, retry_after)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        logger.error(f"[API] Request to {endpoint} failed: {e}")
        raise

# ------------------ Flask Routes ------------------
@app.route('/', methods=['GET'])
def home():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ARAFAT ACCOUNT INFO</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {
                --primary: #FF4655;
                --accent: #00FF94;
                --bg-dark: #0f172a;
                --glass: rgba(255, 255, 255, 0.05);
                --glass-border: rgba(255, 255, 255, 0.1);
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Outfit', sans-serif;
                background-color: var(--bg-dark);
                background-image: 
                    radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                    radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%), 
                    radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
                color: white;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                overflow: hidden;
            }
            .bg-animation {
                position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
                background-size: 40px 40px;
                background-image:
                  linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                  linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            }
            .container {
                position: relative; background: var(--glass);
                backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
                border: 1px solid var(--glass-border); padding: 3rem 2rem;
                border-radius: 24px; text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                max-width: 600px; width: 90%; animation: float 6s ease-in-out infinite;
            }
            h1 {
                font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem;
                background: linear-gradient(to right, #fff, #cbd5e1);
                -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                letter-spacing: -1px; text-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            }
            .badge {
                display: inline-flex; align-items: center; gap: 8px;
                background: rgba(0, 255, 148, 0.1); border: 1px solid rgba(0, 255, 148, 0.2);
                color: var(--accent); padding: 8px 16px; border-radius: 100px;
                font-size: 0.9rem; font-weight: 500; font-family: 'JetBrains Mono', monospace;
                margin-bottom: 2rem; box-shadow: 0 0 15px rgba(0, 255, 148, 0.1);
            }
            .dot {
                width: 8px; height: 8px; background-color: var(--accent);
                border-radius: 50%; animation: pulse 2s infinite;
            }
            .code-box {
                background: rgba(0, 0, 0, 0.3); border: 1px solid var(--glass-border);
                border-radius: 12px; padding: 1.5rem; margin: 0 auto 1rem auto;
                font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
                color: #a5b4fc; word-break: break-all; cursor: pointer; transition: all 0.3s ease;
            }
            .code-box:last-of-type { margin-bottom: 2.5rem; }
            .code-box:hover { border-color: rgba(255, 255, 255, 0.3); transform: translateY(-2px); }
            .footer-links { display: flex; flex-direction: column; gap: 12px; margin-top: 1rem; }
            .btn {
                text-decoration: none; padding: 12px 20px; border-radius: 12px;
                font-weight: 500; transition: all 0.3s ease; display: flex;
                align-items: center; justify-content: center; gap: 10px;
            }
            .btn-credit { background: rgba(255, 255, 255, 0.03); border: 1px solid var(--glass-border); color: #e2e8f0; }
            .btn-credit:hover { background: rgba(255, 255, 255, 0.1); border-color: #e2e8f0; }
            .btn-power {
                background: linear-gradient(45deg, #4f46e5, #06b6d4); color: white;
                box-shadow: 0 10px 20px -10px rgba(79, 70, 229, 0.5);
            }
            .btn-power:hover { filter: brightness(1.1); transform: scale(1.02); box-shadow: 0 15px 30px -10px rgba(79, 70, 229, 0.6); }
            @keyframes pulse {
                0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0.7); }
                70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 255, 148, 0); }
                100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0); }
            }
            @keyframes float {
                0% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
                100% { transform: translateY(0px); }
            }
        </style>
    </head>
    <body>
        <div class="bg-animation"></div>
        <div class="container">
            <h1>Free Fire<br>PLAYER INFO API</h1>
            <div class="badge"><div class="dot"></div>API IS RUNNING</div>
            <div class="code-box" onclick="copyText('/info?uid={uid}')">/info?uid={uid}</div>
            <div class="code-box" onclick="copyText('/wishlist?uid={uid}')">/wishlist?uid={uid}</div>
            <div class="footer-links">
                <a href="https://t.me/arafat_source" target="_blank" class="btn btn-credit">
                    <i class="fab fa-telegram"></i><span>Credit: @arafat_flex</span>
                </a>
                <a href="https://t.me/arafat_source" target="_blank" class="btn btn-power">
                    <i class="fas fa-bolt"></i><span>TELEGRAM CHHANAL: @arafat_flex</span>
                </a>
            </div>
        </div>
        <script>function copyText(text) { navigator.clipboard.writeText(text); }</script>
    </body>
    </html>
    """
    return html_content


@app.route('/info', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'BD').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        api_response = apis(encrypted_hex, region)
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        result = proto_to_dict(message)
        return jsonify(result)
    
    except UpstreamRateLimitError as e:
        payload = {"error": str(e), "status": "rate_limited"}
        if e.retry_after is not None:
            payload["retry_after"] = e.retry_after
        return jsonify(payload), e.status_code
    except requests.Timeout:
        return jsonify({"error": "Upstream server timed out. Please try again.", "status": "upstream_timeout"}), 504
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        logger.error(f"[ERROR] Processing request: {e}")
        return jsonify({"error": "Failure to process the data", "status": "internal_error"}), 500

@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'BD').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        base_endpoint = get_api_endpoint(region)
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")
        
        token = ensure_jwt_token_sync(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = queued_post(wishlist_url, headers=headers, data=bytes.fromhex(encrypted_hex))
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise UpstreamRateLimitError("Wishlist API rate limit reached", 429, retry_after)
        response.raise_for_status()
        resp_hex = response.content.hex()
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(resp_hex))
        
        result = proto_to_dict(res)
        return jsonify(result)

    except UpstreamRateLimitError as e:
        payload = {"error": str(e), "status": "rate_limited"}
        if e.retry_after is not None:
            payload["retry_after"] = e.retry_after
        return jsonify(payload), e.status_code
    except requests.Timeout:
        return jsonify({"error": "Upstream server timed out. Please try again.", "status": "upstream_timeout"}), 504
    except Exception as e:
        logger.error(f"[ERROR] Wishlist request: {e}")
        return jsonify({"error": "Failure to process the wishlist request", "status": "internal_error"}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

# ------------------ Main ------------------
if __name__ == "__main__":
    # For production, use Gunicorn with multiple workers:
    # gunicorn -w 4 -b 0.0.0.0:1080 app:app
    app.run(host="0.0.0.0", port=1080, threaded=True)
