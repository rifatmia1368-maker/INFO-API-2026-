from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from functools import wraps
import queue

from data_pb2 import AccountPersonalShowInfo
from google.protobuf.descriptor import FieldDescriptor
import uid_generator_pb2
import GetWishListItems_pb2

# ------------------ Logging Setup ------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------ Rate Limiting ------------------
rate_limit_store = defaultdict(list)
RATE_LIMIT = 5  # requests per minute per IP
RATE_LIMIT_PERIOD = 60  # seconds

# ------------------ JWT Cache ------------------
jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()

# ------------------ HTTP Session with Retries ------------------
def create_http_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.0,  # Increased for better backoff
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False
    )
    adapter = HTTPAdapter(
        max_retries=retry, 
        pool_connections=10,  # Reduced to prevent overwhelming
        pool_maxsize=10,
        pool_block=True  # Block when pool is exhausted
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

http_session = create_http_session()

# ------------------ Retry Decorator for 429 ------------------
def retry_on_429(max_retries=5):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.RequestException as e:
                    if "429" in str(e) and retries < max_retries - 1:
                        delay = (2 ** retries) + (retries * 0.5)  # Exponential: 1, 2.5, 4.5, 8, 16
                        logger.warning(f"[RETRY] Rate limited. Waiting {delay:.1f}s (attempt {retries + 1}/{max_retries})")
                        time.sleep(delay)
                        retries += 1
                    else:
                        raise
            raise Exception(f"Max retries ({max_retries}) exceeded")
        return wrapper
    return decorator

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
            response = http_session.get(url, timeout=10)
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

def get_wishlist_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetWishListItems",
        "BR": "https://client.us.freefiremobile.com/GetWishListItems",
        "US": "https://client.us.freefiremobile.com/GetWishListItems",
        "SAC": "https://client.us.freefiremobile.com/GetWishListItems",
        "BD": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "ID": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "PK": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "VN": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "ME": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "TH": "https://clientbp.ggpolarbear.com/GetWishListItems",
        "default": "https://clientbp.ggpolarbear.com/GetWishListItems"
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

# Apply retry decorator to API functions
@retry_on_429(max_retries=5)
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
        response = http_session.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        logger.error(f"[API] Request to {endpoint} failed: {e}")
        raise

@retry_on_429(max_retries=5)
def apis_wishlist(idd, region):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_wishlist_endpoint(region)
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
        response = http_session.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        logger.error(f"[API] Wishlist request to {endpoint} failed: {e}")
        raise

# ------------------ Rate Limiting Check ------------------
def check_rate_limit(ip):
    """Check if IP is rate limited"""
    now = time.time()
    # Clean old requests
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_PERIOD]
    
    if len(rate_limit_store[ip]) >= RATE_LIMIT:
        return True
    
    rate_limit_store[ip].append(now)
    return False

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
        # Get client IP for rate limiting
        client_ip = request.remote_addr
        
        # Check rate limit
        if check_rate_limit(client_ip):
            return jsonify({
                "error": f"Rate limit exceeded. Maximum {RATE_LIMIT} requests per {RATE_LIMIT_PERIOD} seconds.",
                "retry_after": RATE_LIMIT_PERIOD
            }), 429
        
        uid = request.args.get('uid')
        region = request.args.get('region', 'BD').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Validate UID
        try:
            uid_int = int(uid)
            if uid_int <= 0:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Invalid UID format. Must be a positive integer."}), 400
        
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = uid_int
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
    
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except requests.exceptions.RequestException as e:
        logger.error(f"[ERROR] API Request failed: {e}")
        if "429" in str(e):
            return jsonify({
                "error": "The Free Fire API is currently rate limiting requests. Please try again in a few minutes.",
                "retry_after": 60
            }), 429
        return jsonify({"error": f"API request failed: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"[ERROR] Processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        # Get client IP for rate limiting
        client_ip = request.remote_addr
        
        # Check rate limit
        if check_rate_limit(client_ip):
            return jsonify({
                "error": f"Rate limit exceeded. Maximum {RATE_LIMIT} requests per {RATE_LIMIT_PERIOD} seconds.",
                "retry_after": RATE_LIMIT_PERIOD
            }), 429
        
        uid = request.args.get('uid')
        region = request.args.get('region', 'BD').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Validate UID
        try:
            uid_int = int(uid)
            if uid_int <= 0:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Invalid UID format. Must be a positive integer."}), 400

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = uid_int
        
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        api_response = apis_wishlist(encrypted_hex, region)
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(api_response))
        
        result = proto_to_dict(res)
        return jsonify(result)

    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except requests.exceptions.RequestException as e:
        logger.error(f"[ERROR] Wishlist API Request failed: {e}")
        if "429" in str(e):
            return jsonify({
                "error": "The Free Fire API is currently rate limiting requests. Please try again in a few minutes.",
                "retry_after": 60
            }), 429
        return jsonify({"error": f"API request failed: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"[ERROR] Wishlist request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

# ------------------ Health Check Endpoint ------------------
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "rate_limit": {
            "requests_per_minute": RATE_LIMIT,
            "current_connections": len(rate_limit_store)
        },
        "jwt_status": {
            region: "valid" if token and time.time() < jwt_expiry.get(region, 0) else "expired"
            for region, token in jwt_tokens.items()
        }
    }), 200

# ------------------ Main ------------------
if __name__ == "__main__":
    logger.info("Starting Free Fire API Server...")
    logger.info(f"Rate Limit: {RATE_LIMIT} requests per {RATE_LIMIT_PERIOD} seconds per IP")
    logger.info("Server running on http://0.0.0.0:1080")
    
    # For production, use Gunicorn with multiple workers:
    # gunicorn -w 4 -b 0.0.0.0:1080 app:app
    app.run(host="0.0.0.0", port=1080, threaded=True, debug=False)
