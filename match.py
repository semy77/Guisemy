#═══════════════════════════════════════════════════════════════════════════
#  match.py — Final (offline + fresh TCP + cache login + auto-repeat ∞)
#  3 match-end detection fixes applied
#  Owner: AVI CODEX | Telegram: @AVI_CODEXX
# ═══════════════════════════════════════════════════════════════════════════

import asyncio
import socket
import struct
import time
import json
import os
import math
import sys
import random
import itertools
import base64
import re
import hmac
import hashlib
import uuid
import ssl
import traceback
import collections
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from protobuf_decoder.protobuf_decoder import Parser
    _HAS_PARSER = True
except ImportError:
    _HAS_PARSER = False
    Parser = None

try:
    from message_ids import MESSAGE_ID_TO_NAME
except ImportError:
    MESSAGE_ID_TO_NAME = {}

try:
    import StartMatch_pb2
    _START_MATCH_PROTO = StartMatch_pb2
except ImportError:
    _START_MATCH_PROTO = None

from core import (
    _log,
    enc_aes, dec_aes,
    enc_varint, read_varint,
    ptag, f_vint, f_bytes, f_str,
    parse_proto, first_value,
    decode_jwt_payload,
    build_region_cfg,
    major_login, get_login_data,
    load_squad_accounts,
    _to_bytes,
    HARDCODED_CONFIG, _PLAY_VERSION, _OB_VERSION,
    REGION_LANG, REGION_GROUP, REGION_LIST,
    region_byte, region_prefix,
    get_guest_token as core_get_guest_token,
    SECRET, APP_ID, CLIENT_TYPE,
    _normalize_uid,
)

# ═══════════════ CONSTANTS ═══════════════
# ═══ CHANGE 1: 3000 → 700 (11.6 min hard cap) ═══
MAX_MATCH_DURATION      = 700
# ═══ CHANGE 2: 150.0 → 30.0 (30s idle timeout) ═══
MATCH_IDLE_TIMEOUT      = 30.0
HANDSHAKE_TIMEOUT       = 45.0
EXP_REFRESH_AFTER_MATCH_DELAY = 9.0
NON_MATCH_RECONNECT_DELAY      = 1.0
SESSION_RETRY_DELAY            = 3.0
AFTER_MATCH_COOLDOWN           = 3.0

BR_MODE_ID = 1
BR_MAP_ID  = 1

ANTI_AFK_MIN_INTERVAL = 1.8
ANTI_AFK_MAX_INTERVAL = 3.5

MATCH_SEARCH_TIMEOUT = 90.0
MATCH_WATCHDOG_CHECK = 30.0
REGION_ROTATION_LIST = ["IND", "ID", "SG", "TH", "MY", "VN", "PH"]
REGION_ROTATE_EVERY_N = 2
MAX_SEARCH_ATTEMPTS = 25

SAFE_PLAY_MODE        = True
BYPASS_TIMING_JITTER  = True
BYPASS_PACKET_JITTER  = True
BYPASS_HELLO_DELAY    = True
BYPASS_KA_JITTER      = True

# ═══════════════ NEW MOVEMENT ═══════════════
AUTO_MOVE_ENABLED = True
AUTO_MOVE_START_DELAY = 5.0
AUTO_MOVE_SPAWN_TIMEOUT = 30.0
AUTO_MOVE_LAND_TIMEOUT = 8.0
AUTO_MOVE_TICK_INTERVAL = 0.1
AUTO_MOVE_WALK_SPEED = 352
AUTO_MOVE_RUN_SPEED = 546
AUTO_MOVE_RUN_CHANCE = 0.6
AUTO_MOVE_RADIUS = 6000
AUTO_MOVE_MIN_LEG = 1500
AUTO_MOVE_TURN_PER_TICK = 25.0
AUTO_MOVE_PAUSE_RANGE = (0.6, 2.5)
AUTO_MOVE_RESYNC_DISTANCE = 2500
AUTO_MOVE_PIGGYBACK_ACK = True
AUTO_MOVE_MSG_KEYS = list(range(0x64, 0x6E))
AUTO_MOVE_DEFAULT_RTT = 120

MSG_PLAYER_STATE_SYNC = 2001

ENABLE_HTTP_PING = True
PING_INTERVAL    = 20.0
PING_TIMEOUT     = 8.0
PING_URL         = "https://loginbp.ppmainecoonghj.com/Ping"
PING_REAL_IP     = "103.109.214.211"

TEAM_MODE               = True
TEAM_SIZE               = 4
TEAM_PEER_WAIT_TIMEOUT  = 15.0
TEAM_CREATE_WAIT        = 3.0
TEAM_INVITE_CYCLE_WAIT  = 2.5
TEAM_INVITE_MAX_TIME    = 12.0
TEAM_HEARTBEAT_INTERVAL = 4.0
TEAM_IDLE_ITERS_TEAM    = 1800
TEAM_MEMBER_START_DELAY = 4.0
TEAM_FINAL_WAIT         = 12.0
TEAM_READY_DELAY        = 3.0

FORCED_CLIENT_VERSION = "2.133.13"

# ═══════════════ LOGIN CACHE ═══════════════
LOGIN_CACHE_FILE = "squad_accounts_cache.json"
CACHE_TTL = 24 * 3600

_login_cache: Dict[str, dict] = {}
_login_cache_lock = asyncio.Lock()


def _load_login_cache_file():
    global _login_cache
    if not os.path.exists(LOGIN_CACHE_FILE):
        _login_cache = {}
        return
    try:
        with open(LOGIN_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _login_cache = data
            print_info(f"[CACHE] loaded {len(_login_cache)} cached login(s) from {LOGIN_CACHE_FILE}")
        else:
            _login_cache = {}
    except Exception as e:
        print_warning(f"[CACHE] load failed: {e}")
        _login_cache = {}


def _save_login_cache_file():
    try:
        with open(LOGIN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_login_cache, f, indent=2)
    except Exception as e:
        print_warning(f"[CACHE] save failed: {e}")


def _cache_get(uid: str) -> Optional[dict]:
    rec = _login_cache.get(str(uid))
    if not rec:
        return None
    if time.time() - rec.get("cached_at", 0) > CACHE_TTL:
        return None
    for k in ("account_id", "token", "aes_ak", "iv_i", "game_server", "region"):
        if k not in rec or not rec[k]:
            return None
    rec["cached_at"] = time.time()
    _login_cache[str(uid)] = rec
    try:
        _save_login_cache_file()
    except Exception:
        pass
    return rec


def _cache_put(uid: str, data: dict):
    rec = dict(data)
    rec["cached_at"] = time.time()
    if isinstance(rec.get("aes_ak"), (bytes, bytearray)):
        rec["aes_ak"] = rec["aes_ak"].hex()
    if isinstance(rec.get("iv_i"), (bytes, bytearray)):
        rec["iv_i"] = rec["iv_i"].hex()
    _login_cache[str(uid)] = rec
    _save_login_cache_file()


def _cache_hydrate(rec: dict) -> dict:
    out = dict(rec)
    try:
        if isinstance(out.get("aes_ak"), str):
            out["aes_ak"] = bytes.fromhex(out["aes_ak"])
        if isinstance(out.get("iv_i"), str):
            out["iv_i"] = bytes.fromhex(out["iv_i"])
    except Exception:
        pass
    return out


# ═══════════════ COLORS / PRINT ═══════════════
class Colors:
    GREEN='\033[92m'; FAIL='\033[91m'; WARNING='\033[93m'
    CYAN='\033[96m'; MAGENTA='\033[95m'; WHITE='\033[97m'; ENDC='\033[0m'

def print_colored(t, c=Colors.WHITE):
    try: print(f"{c}{t}{Colors.ENDC}", flush=True)
    except Exception: pass

def print_success(t): print_colored(f"[+] {t}", Colors.GREEN)
def print_error(t):   print_colored(f"[-] {t}", Colors.FAIL)
def print_warning(t): print_colored(f"[!] {t}", Colors.WARNING)
def print_info(t):    print_colored(f"[i] {t}", Colors.CYAN)

def banner_team_code(team_code, uid=""):
    if not team_code: return
    box_w = 50
    line = "═" * box_w
    print_colored(f"╔{line}╗", Colors.GREEN)
    title = f"  🎯 TEAM CODE: {team_code}  "
    pad_n = max(0, (box_w - len(title)) // 2)
    print_colored(f"║{' ' * pad_n}{title}{' ' * (box_w - pad_n - len(title))}║", Colors.GREEN)
    if uid:
        s = f"  Leader: {uid}"
        print_colored(f"║{s:<{box_w}}║", Colors.CYAN)
    print_colored(f"╚{line}╝", Colors.GREEN)

def bypass_jitter(base, spread=0.35):
    if not (SAFE_PLAY_MODE and BYPASS_TIMING_JITTER): return base
    return max(0.05, base + random.uniform(-spread, spread))

def bypass_packet_jitter(base, spread_ratio=0.35):
    if not (SAFE_PLAY_MODE and BYPASS_PACKET_JITTER): return base
    return max(0.1, base + random.uniform(-base * spread_ratio, base * spread_ratio))

def bypass_hello_delay():
    if not (SAFE_PLAY_MODE and BYPASS_HELLO_DELAY): return 0.0
    return random.uniform(0.05, 0.45)

def bypass_ka_jitter(base=5.0):
    if not (SAFE_PLAY_MODE and BYPASS_KA_JITTER): return base
    return max(3.0, base + random.uniform(-0.8, 1.2))

def bypass_human_reconnect_delay(attempt):
    if not (SAFE_PLAY_MODE and BYPASS_TIMING_JITTER): return min(attempt * 0.5, 2.0)
    return max(0.05, min(attempt * 0.5, 2.0) + random.uniform(-0.4, 0.7))

# ═══════════════ HTTP / KEYS ═══════════════
_aiohttp_session = None

async def get_aiohttp_session():
    global _aiohttp_session
    if _aiohttp_session is None or _aiohttp_session.closed:
        _aiohttp_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=100))
    return _aiohttp_session

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

CRC7_TABLE = bytes([
    0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,25,16,11,2,61,52,47,38,
    81,88,67,74,117,124,103,110,50,59,32,41,22,31,4,13,122,115,104,97,94,87,76,69,
    43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,100,109,118,127,64,73,82,91,
    44,37,62,55,8,1,26,19,125,116,111,102,89,80,75,66,53,60,39,46,17,24,3,10,
    86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,79,70,93,84,107,98,121,112,
    7,14,21,28,35,42,49,56,65,72,83,90,101,108,119,126,9,0,27,18,45,36,63,54,
    88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,47,115,122,97,104,87,94,69,76,
    59,50,41,32,31,22,13,4,106,99,120,113,78,71,92,85,34,43,48,57,6,15,20,29,
    37,44,55,62,1,8,19,26,109,100,127,118,73,64,91,82,60,53,46,39,24,17,10,3,
    116,125,102,111,80,89,66,75,23,30,5,12,51,58,33,40,95,86,77,68,123,114,105,96,
    14,7,28,21,42,35,56,49,70,79,84,93,98,107,112,121,
])
_DELTA = 0x9E3779B9
_ROUNDS = 16
_FIELD_SIZES = {0:1, 1:2, 2:2, 3:1, 4:2}
_FIELD_NAMES = {0:"sendOption", 1:"cmd", 2:"orderId", 3:"flags", 4:"length"}

# ═══════════════ TEAM CODE EXTRACTION ═══════════════
def extract_team_code_from_bytes(buf: bytes) -> Optional[str]:
    if not buf or len(buf) < 5: return None
    m = re.search(rb'\x5a[\x06\x07\x08]([0-9]{6,8})', buf)
    if m:
        c = m.group(1).decode('ascii', 'ignore')
        if c.isdigit() and 6 <= len(c) <= 8: return c
    m2 = re.search(rb'(?:[\x30-\x39]{7})', buf)
    if m2:
        c = m2.group(0).decode('ascii', 'ignore')
        if c.isdigit() and len(c) == 7: return c
    try:
        idx = 0
        while idx < len(buf) - 4:
            if buf[idx] == 0x52:
                length = buf[idx + 1]
                if 6 <= length <= 8 and idx + 2 + length <= len(buf):
                    c = buf[idx + 2:idx + 2 + length].decode('ascii', 'ignore')
                    if c.isdigit() and 6 <= len(c) <= 8: return c
            idx += 1
    except Exception: pass
    return None

def _decode_proto_manual(data):
    result = {}; offset = 0; dl = len(data)
    while offset < dl:
        header = 0; shift = 0
        while offset < dl:
            b = data[offset]; offset += 1
            header |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
            if shift > 28: break
        if header == 0: break
        fn = header >> 3; wt = header & 0x7
        if fn == 0: break
        if wt == 0:
            v = 0; shift = 0
            while offset < dl:
                b = data[offset]; offset += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
                if shift > 63: break
            result[fn] = v
        elif wt == 2:
            length = 0; shift = 0
            while offset < dl:
                b = data[offset]; offset += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
                if shift > 28: break
            if length > dl - offset: break
            value = data[offset:offset+length]; offset += length
            try:
                s = value.decode('utf-8')
                if s and all(31 < ord(c) < 127 or ord(c) in (9, 10, 13) for c in s):
                    result[fn] = s
                else:
                    nested = _decode_proto_manual(value)
                    result[fn] = nested if nested else value.hex()
            except UnicodeDecodeError:
                nested = _decode_proto_manual(value)
                result[fn] = nested if nested else value.hex()
        elif wt == 5: offset += 4
        elif wt == 1: offset += 8
        else: break
    return result

def _wrap_manual(inner):
    try:
        alt = _decode_proto_manual(inner)
        if alt and len(alt) > 0:
            return {str(k): {"data": v} for k, v in alt.items()}
    except Exception: pass
    return None

# ═══════════════ SQUAD GROUP ═══════════════
class TeamGroup:
    def __init__(self, gid: int, size: int = TEAM_SIZE):
        self.gid = gid
        self.size = max(1, min(int(size), TEAM_SIZE))
        self.peers: Dict[str, Any] = {}
        self.leader_uid: Optional[str] = None
        self.team_code: Optional[str] = None
        self.pk_code: Optional[str] = None
        self.members: set = set()
        self.members_lock = asyncio.Lock()
        self.lock = asyncio.Lock()
        self.active = {"flag": True}

    def tag(self) -> str:
        return f"G{self.gid}"

async def team_member_join(grp: TeamGroup, uid):
    uid = str(uid)
    async with grp.members_lock:
        before = len(grp.members)
        grp.members.add(uid)
        after = len(grp.members)
    if after != before:
        print_success(f"[TEAM-{grp.tag()}] 👥 In team ({after}/{grp.size}) | joined: {uid}")
    return after

async def team_member_leave(grp: TeamGroup, uid):
    async with grp.members_lock:
        grp.members.discard(str(uid))

async def team_member_count(grp: TeamGroup):
    async with grp.members_lock:
        return len(grp.members)

async def team_member_reset(grp: TeamGroup, keep_leader=True):
    async with grp.members_lock:
        grp.members.clear()
        if keep_leader and grp.leader_uid:
            grp.members.add(grp.leader_uid)

# ═══════════════ MATCH COUNTER ═══════════════
_match_counters: Dict[str, int] = {}
_match_counter_lock = asyncio.Lock()

async def _inc_match(uid):
    async with _match_counter_lock:
        _match_counters[uid] = _match_counters.get(uid, 0) + 1
        return _match_counters[uid]

async def _dec_match(uid):
    async with _match_counter_lock:
        if uid in _match_counters and _match_counters[uid] > 0:
            _match_counters[uid] -= 1
        return _match_counters.get(uid, 0)

async def _get_match_count(uid):
    async with _match_counter_lock:
        return _match_counters.get(uid, 0)

# ═══════════════ CRYPTO / PROTOBUF ═══════════════
async def aes_encrypt(payload, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, AES.block_size))

def encode_varint(n):
    out = bytearray()
    if n < 0: n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, val): return encode_varint((fn << 3) | 0) + encode_varint(val)
def _pb_length(fn, val):
    enc = val.encode('utf-8') if isinstance(val, str) else val
    return encode_varint((fn << 3) | 2) + encode_varint(len(enc)) + enc

def create_proto(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str): field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict): packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str): packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool): packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int): packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool): packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int): packet.extend(_pb_varint(field, value))
        elif isinstance(value, str): packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)

def encrypt_api(plain_hex):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(
        pad(bytes.fromhex(plain_hex), AES.block_size)).hex()

def create_packet(Pk, N, K, V):
    if isinstance(K, str): K = bytes.fromhex(K) if len(K) == 32 else K.encode()
    if isinstance(V, str): V = bytes.fromhex(V) if len(V) == 32 else V.encode()
    PkEnc = AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(Pk), 16)).hex()
    L = len(PkEnc) // 2
    hexlen = hex(L)[2:]
    if len(hexlen) % 2 != 0: hexlen = '0' + hexlen
    pad_len = 12 - len(N) - len(hexlen)
    if pad_len < 0: pad_len = 0
    return bytes.fromhex(N + ('0' * pad_len) + hexlen + PkEnc)

# ═══════════════ DECODE HELPERS ═══════════════
def decode_varint(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80): return result, offset
        shift += 7
    return None, offset

def decode_zigzag(n: int) -> int:
    return (n >> 1) ^ (-(n & 1))

def zigzag_decode(n: int) -> int:
    return (n >> 1) ^ (-(n & 1))

def _parse_results_sync(results):
    out = {}
    for r in results:
        fd = {"wire_type": r.wire_type}
        if r.wire_type == "varint": fd["data"] = r.data
        elif r.wire_type in ("string", "bytes"): fd["data"] = r.data
        elif r.wire_type == "length_delimited":
            if hasattr(r.data, "results"): fd["data"] = _parse_results_sync(r.data.results)
            elif isinstance(r.data, list): fd["data"] = _parse_results_sync(r.data)
            else: fd["data"] = str(r.data)
        out[str(r.field)] = fd
    return out

def decode_protobuf_dict(data: bytes) -> dict:
    if not _HAS_PARSER: return {}
    try: return _parse_results_sync(Parser().parse(data))
    except Exception: return {}

async def decode_protobuf(data):
    if not _HAS_PARSER: return "{}"
    try:
        parsed = Parser().parse(data)
        return json.dumps(_parse_results_sync(parsed))
    except Exception:
        return "{}"

# ═══════════════ DNS / SOCKETS ═══════════════
_DNS_CACHE: Dict[str, Tuple[str, float]] = {}
_DNS_CACHE_TTL = 300.0

async def resolve_host_cloudflare(hostname):
    if not hostname: return hostname
    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts): return hostname
    now = time.time()
    if hostname in _DNS_CACHE:
        ip, exp = _DNS_CACHE[hostname]
        if now < exp: return ip
    try:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if info:
            ip = info[0][4][0]
            _DNS_CACHE[hostname] = (ip, now + _DNS_CACHE_TTL)
            return ip
    except Exception: pass
    return hostname

def optimize_tcp_socket(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
    except Exception: pass

def optimize_udp_socket(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
    except Exception: pass

async def safe_close_writer(writer):
    if not writer: return
    try:
        if not writer.is_closing(): writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.5)
    except Exception: pass

# ═══════════════ LOGIN (with cache) ═══════════════
async def login_via_core(uid, password, region_override=None):
    uid_s = str(uid)

    async with _login_cache_lock:
        cached = _cache_get(uid_s)
    if cached:
        print_info(f"[CACHE-HIT] {uid_s} using cached login (age {int(time.time()-cached.get('cached_at',0))}s)")
        return _cache_hydrate(cached)

    region = (region_override or "IND").upper()
    try:
        open_id, access_token, platform = await core_get_guest_token(uid, password)
    except Exception as e:
        raise RuntimeError(f"guest token failed: {e}")
    platform = int(platform or 4)
    cfg_local = build_region_cfg(region)
    try:
        login = await asyncio.to_thread(
            major_login, "[login]", open_id, access_token, cfg_local,
            platform, region)
    except Exception as e:
        raise RuntimeError(f"MajorLogin failed: {e}")
    jwt = login.get("jwt")
    if not jwt:
        raise RuntimeError("MajorLogin returned no JWT")
    base_url = login.get("game_url") or cfg_local["server_url"]
    payload = decode_jwt_payload(jwt) if jwt else {}
    lock_reg = (payload.get("lock_region") or region).upper()
    if lock_reg != region:
        region = lock_reg
        cfg_local = build_region_cfg(region)
        try:
            login = await asyncio.to_thread(
                major_login, "[login]", open_id, access_token, cfg_local,
                platform, region)
        except Exception as e:
            raise RuntimeError(f"MajorLogin (relock) failed: {e}")
        jwt = login.get("jwt")
        base_url = login.get("game_url") or cfg_local["server_url"]
    try:
        ld = await asyncio.to_thread(
            get_login_data, "[login]", open_id, access_token, cfg_local,
            platform, jwt)
    except Exception as e:
        raise RuntimeError(f"GetLoginData failed: {e}")
    aes_ak = _to_bytes(login.get("aes_key") or b"")
    iv_i   = _to_bytes(login.get("aes_iv") or b"")
    if not aes_ak or not iv_i:
        raise RuntimeError("AES key/iv missing from MajorLogin")
    game_server = ld.get("game_server")
    if not game_server:
        raise RuntimeError("game_server missing from GetLoginData")
    acc_id = login.get("account_id")
    result = {
        "account_id": acc_id,
        "account_id_numeric": int(acc_id) if acc_id else 0,
        "token": jwt,
        "server_url": base_url,
        "aes_ak": aes_ak,
        "iv_i": iv_i,
        "region": region,
        "server_time": login.get("server_time", 0),
        "game_server": game_server,
        "chat_server": ld.get("chat_server"),
        "nickname": ld.get("nickname") or f"Player_{acc_id}",
        "open_id": open_id,
        "access_token": access_token,
        "uid": str(uid),
        "platform": platform,
        "client_version": cfg_local.get("remote_version") or FORCED_CLIENT_VERSION,
        "release_version": cfg_local.get("latest_release_version") or "OB55",
    }

    async with _login_cache_lock:
        _cache_put(uid_s, result)
    print_info(f"[CACHE-SAVE] {uid_s} fresh login cached")

    return result

# ═══════════════ HTTP PING ═══════════════
async def send_ping(account_id, token, release_version, ping_url=None):
    try:
        try: acc = int(account_id)
        except Exception: acc = 0
        now_ms = int(time.time() * 1000)
        payload = struct.pack("<Q", acc & 0xFFFFFFFFFFFFFFFF) + struct.pack("<Q", now_ms & 0xFFFFFFFFFFFFFFFF)
        req_id = uuid.uuid4().hex[:22]
        hdrs = {
            'accept': '*/*', 'accept-encoding': 'deflate, gzip',
            'authorization': f'Bearer {token}',
            'content-type': 'application/x-www-form-urlencoded',
            'releaseversion': release_version or "OB55",
            'user-agent': 'UnityPlayer/2018.4.12f1',
            'x-ga': 'v1 1', 'x-ga-sv': str(int(time.time())),
            'x-railway-edge': 'sin1', 'x-railway-request-id': req_id,
            'x-real-ip': PING_REAL_IP, 'x-request-start': str(now_ms),
            'x-unity-version': '2018.4.12f1',
        }
        s = await get_aiohttp_session()
        async with s.post(str(ping_url or PING_URL), headers=hdrs, data=payload,
                          timeout=aiohttp.ClientTimeout(total=PING_TIMEOUT)) as r:
            return r.status == 200
    except Exception: return False

async def ping_worker(account_id, token, release_version, region="IND", ping_url=None, stop_event=None):
    if not ENABLE_HTTP_PING: return
    uid_str = str(account_id)
    try:
        await asyncio.sleep(5.0 + random.uniform(0, 2.0))
        while stop_event is None or not stop_event.is_set():
            await send_ping(uid_str, token, release_version, ping_url)
            await asyncio.sleep(max(5.0, PING_INTERVAL + random.uniform(-3.0, 3.0)))
    except asyncio.CancelledError: pass

# ═══════════════ TCP STARTUP ═══════════════
async def build_tcp_startup_packet(account_id, token, server_time, key, iv, region="IND", typ='OnLine'):
    uid_hex = f"{int(account_id):016x}"
    ts_hex = f"{int(server_time):08x}"
    enc = (await aes_encrypt(token.encode(), key, iv)).hex()
    enc_len = f"{len(enc)//2:08x}"
    reg = str(region).upper() if region else "IND"
    if typ == 'OnLine':
        pfx = '7219' if reg == 'BD' else ('7214' if reg == 'IND' else '7215')
        return f"{pfx}{uid_hex}{ts_hex}00000000{enc_len}{enc}"
    pfx = '8119' if reg == 'BD' else ('8114' if reg == 'IND' else '8115')
    return f"{pfx}{uid_hex}{ts_hex}{enc_len}{enc}"

async def send_keep_alive(region="IND"):
    try:
        reg = str(region).upper() if region else "IND"
        return bytes.fromhex("0219" if reg == "BD" else ("0214" if reg == "IND" else "0215"))
    except Exception:
        return bytes.fromhex("0215")

# ═══════════════ VARINT / ZIGZAG / ULEB ═══════════════
async def has_ssan_zig(n):
    z = (n << 1) & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while z >= 0x80: out.append((z & 0x7F) | 0x80); z >>= 7
    out.append(z); return bytes(out)

async def uleb_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

async def zigzag_encode(n: int) -> bytes:
    z = (n << 1) if n >= 0 else ((-n) << 1) - 1
    out = bytearray()
    while True:
        b = z & 0x7F; z >>= 7
        if z: b |= 0x80
        out.append(b)
        if not z: break
    return bytes(out)

# ═══════════════ TEAM PACKETS ═══════════════
def create_team(key, iv, game_version="1.132.13"):
    fields = {
        1: 1, 2: {2: bytes.fromhex("01"), 3: 1, 4: 3, 5: "en",
            8: {1: "IDC3", 2: 123, 3: "IND"}, 9: 1,
            10: bytes.fromhex("01090a0b1219202729"), 11: 2, 13: 1,
            14: {1: "08FBA33B4BABE2790205390333330000009700050092005F72697EB2134DCBB2467625142201040e38e848dc0e748c3f6aa04d81000000ff1113090dcacfa16d",
                 2: 478, 3: "7e585d55", 4: "y[Z]", 6: 12, 7: "15686677735a7506101c",
                 8: str(game_version), 9: 3, 10: 1, 11: "03626253513637754174"},
            19: 329, 21: bytes.fromhex("374f521955"), 24: {1: 21},
            27: "a_6534489873065906362"}}
    return create_packet(create_proto(fields).hex(), "0515", key, iv)

def team_fresh(account_id, key, iv):
    return create_packet(create_proto({1: 72, 2: {1: int(account_id)}}).hex(), "0515", key, iv)

def invite_player_in_team(target_uid, key, iv, region="IND"):
    return create_packet(create_proto({1: 2, 2: {1: int(target_uid), 2: region, 4: 1}}).hex(),
                         "0515", key, iv)

def accept_team_invite(target_uid, group_id, key, iv):
    fields = {1: 4, 2: {1: int(target_uid), 3: int(target_uid),
        4: bytes.fromhex("0107090a0b120f19202729"), 8: 1,
        9: {1: "08FBA33B0522052002041B0222220007000C00010004000547E265AE1080779546762514110104076fa2e8770e748c3f6a68ed75000000ff08080500cacfa16d",
            2: 235, 3: {14: 80, 11: 86}, 4: "{Y\\R", 6: 13, 7: {2: 4},
            8: "1.132.13", 9: 2, 10: 1, 11: "0362625351"},
        10: str(group_id),
        11: {"1": "IDC3", "2": 107, "3": "IND"}, 13: "en", 16: "374f5219",
        20: {1: 21}, 23: "a_6534489873065906362",
        24: "https://dl-sg-production.freefiremobile.com/",
        27: {1: 2, 2: 4}}}
    return create_packet(create_proto(fields).hex(), "0515", key, iv)

def start_match_team(account_id, key, iv, region="IND"):
    fields = {1: 9, 2: {1: int(account_id), 7: {1: "IDC3", 2: 410, 3: region}}}
    return create_packet(create_proto(fields).hex(), "0515", key, iv)

def ready_for_game(uid, key, iv):
    return create_packet(create_proto({1: 15, 2: {1: uid, 2: 1}}).hex(), "0519", key, iv)

# ═══════════════ START MATCH ═══════════════
def build_start_match_v2(account_id, uid, name, server_ip_port, udp_key, jwt_token,
                         match_code="04312", region="IND", mode=5, map_id=41000,
                         team_size=4, key=None, iv=None, framed=True) -> bytes:
    fields = {
        1: int(account_id), 2: str(server_ip_port), 3: str(udp_key),
        4: str(jwt_token), 5: int(mode), 6: 1, 7: 1, 8: 1, 13: 1,
        42: str(match_code), 44: 1, 45: int(team_size), 46: int(map_id),
    }
    proto_hex = create_proto(fields).hex()
    if framed and key and iv:
        return create_packet(proto_hex, "0515", key, iv)
    return proto_hex

# ═══════════════ UDP TEA ═══════════════
async def tea_enc(v0, v1, k0, k1, k2, k3):
    s = 0
    for _ in range(_ROUNDS):
        s = (s + _DELTA) & 0xFFFFFFFF
        v0 = (v0 + ((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF
                    ^ ((v1 + s) & 0xFFFFFFFF)
                    ^ (((v1 >> 5) + k1) & 0xFFFFFFFF))) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF
                    ^ ((v0 + s) & 0xFFFFFFFF)
                    ^ (((v0 >> 5) + k3) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return v0, v1

async def tea_dec(v0, v1, k0, k1, k2, k3):
    s = (_DELTA * _ROUNDS) & 0xFFFFFFFF
    for _ in range(_ROUNDS):
        v1 = (v1 - ((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF
                    ^ ((v0 + s) & 0xFFFFFFFF)
                    ^ (((v0 >> 5) + k3) & 0xFFFFFFFF))) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF
                    ^ ((v1 + s) & 0xFFFFFFFF)
                    ^ (((v1 >> 5) + k1) & 0xFFFFFFFF))) & 0xFFFFFFFF
        s = (s - _DELTA) & 0xFFFFFFFF
    return v0, v1

async def tea_cbc_encrypt(padded, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(padded))
    prev_cipher = bytearray(8)
    prev_intermediate = bytearray(8)
    for i in range(0, len(padded), 8):
        xored = bytearray(8)
        for j in range(8):
            xored[j] = padded[i + j] ^ prev_cipher[j]
        e0, e1 = await tea_enc(struct.unpack_from("<I", xored, 0)[0],
                               struct.unpack_from("<I", xored, 4)[0],
                               k0, k1, k2, k3)
        enc = bytearray(8)
        struct.pack_into("<I", enc, 0, e0)
        struct.pack_into("<I", enc, 4, e1)
        for j in range(8):
            out[i + j] = enc[j] ^ prev_intermediate[j]
        prev_cipher[:] = out[i:i + 8]
        prev_intermediate[:] = xored
        if i % 64 == 0:
            await asyncio.sleep(0)
    return bytes(out)

async def tea_cbc_decrypt(body, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(body))
    prev_intermediate = bytearray(8)
    prev_cipher = bytearray(8)
    xored = bytearray(8)
    dec = bytearray(8)
    for i in range(0, len(body), 8):
        for j in range(8):
            xored[j] = body[i + j] ^ prev_intermediate[j]
        d0, d1 = await tea_dec(struct.unpack_from("<I", xored, 0)[0],
                               struct.unpack_from("<I", xored, 4)[0],
                               k0, k1, k2, k3)
        struct.pack_into("<I", dec, 0, d0)
        struct.pack_into("<I", dec, 4, d1)
        for j in range(8):
            out[i + j] = dec[j] ^ prev_cipher[j]
        prev_cipher[:] = body[i:i + 8]
        prev_intermediate[:] = dec
        if i % 64 == 0:
            await asyncio.sleep(0)
    return bytes(out)

async def build_padded(content):
    pad_len = (8 - (len(content) + 10) % 8) % 8
    return bytes([pad_len, 0, 0]) + b"\x00" * pad_len + content + b"\x00" * 7

async def oicq_unpad(padded):
    if not padded or len(padded) < 8:
        return None
    if not all(padded[-1 - i] == 0 for i in range(7)):
        return None
    pad_len = padded[0] & 0x07
    s = 3 + pad_len
    e = len(padded) - 7
    return padded[s:e] if s < e else b""

async def encode_header(layout, so, cmd, oid, flags, length, k, v80):
    out = bytearray()
    for code in layout:
        value = {0: so, 1: cmd, 2: oid, 3: flags, 4: length}[code]
        if _FIELD_SIZES[code] == 1:
            out.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            out.append(v & 0xFF)
            out.append((v >> 8) & 0xFF)
    return bytes(out)

async def layouts_from_mask(mask):
    s = str(mask).strip()
    try:
        ru = [int(c) for c in s]
    except ValueError:
        ru = [0, 1, 2, 3, 4]
    if sorted(ru) != [0, 1, 2, 3, 4]:
        ru = [0, 1, 2, 3, 4]
    return ru, [c for c in ru if c != 2]

async def crc7_buff(crc, buf):
    c = crc & 0x7F
    for b in buf:
        c = CRC7_TABLE[((2 * (c & 0xFF)) ^ (b & 0xFF)) & 0xFF] & 0x7F
    return c & 0x7F

async def build_packet(msg_key, layout, so, cmd, oid, flags, content, key, encrypted=True):
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    body = await tea_cbc_encrypt(await build_padded(content), key) if encrypted else content
    hdr = bytearray([msg_key, 0])
    for code in layout:
        value = {0: so, 1: cmd, 2: oid, 3: flags, 4: len(body)}[code]
        if _FIELD_SIZES[code] == 1:
            hdr.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            hdr.append(v & 0xFF)
            hdr.append((v >> 8) & 0xFF)
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)

async def build_hello_packet(text, key, layout):
    data = text.encode("utf-8")[:25]
    content = len(data).to_bytes(4, "little") + data + b"\x00" * 9
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    layout = [int(c) for c in str(layout).strip()]
    enc_body = await tea_cbc_encrypt(await build_padded(content), key)
    header_bytes = await encode_header(layout, 1, 1, 0, 1, len(enc_body), k, v80)
    packet = bytearray([0x63, 0x00]) + header_bytes + enc_body
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet).hex()

async def sv_frame(msg_key, layout, so, cmd, oid, flags, content, key, encrypted=True):
    return await build_packet(msg_key, layout, so, cmd, oid, flags, content, key, encrypted)

async def build_match_startup_packets(token, udp_key, match_code, account_id, block_val,
                                      server_ip="", region="IND", client_version="1.132.13",
                                      client_version_code="2019121229", access_token="",
                                      mode_id=BR_MODE_ID, map_id=BR_MAP_ID):
    token = token.strip()
    udp_key = bytes.fromhex(udp_key)
    match_code = [int(ch) for ch in str(match_code).strip()]
    thunder_jwt = token[:660] if len(token) > 660 else token
    sharma_jwt = token[660:] if len(token) > 660 else ""
    eth = thunder_jwt.encode() if isinstance(thunder_jwt, str) else thunder_jwt
    esh = sharma_jwt.encode() if isinstance(sharma_jwt, str) else sharma_jwt
    garena420 = await has_ssan_zig(len(eth)) + eth
    reg = str(region).upper() if region else "IND"
    csoversea_block = bytes.fromhex(
        "ca0163736f7665727365612e7374726f6e67686f6c642e66726565666972656d6f62696c652e636f6d"
        "3b302e302e302e303b33342e3132362e37362e34353b33342e38372e3137372e31343b33342e38372e"
        "3137302e3233303b33352e3138352e3138332e35370000000000000100000000000000000000000001"
        "00000800000100000000000100a8a2d7bebd8d8bdf110200")
    mid = bytes.fromhex('0000000001000102030101') + await has_ssan_zig(len(reg)) + reg.encode()
    mid += bytes.fromhex('0001030003000004')
    mid += await has_ssan_zig(len(client_version)) + client_version.encode()
    mid += await has_ssan_zig(len(client_version_code)) + client_version_code.encode()
    mid += csoversea_block
    clean_ip = server_ip.split(':')[0] if server_ip else "0.0.0.0"
    mid += await has_ssan_zig(len(clean_ip)) + clean_ip.encode()
    if access_token:
        clean_acc = access_token.strip()
        mid += await has_ssan_zig(len(clean_acc)) + clean_acc.encode()
    mid += await has_ssan_zig(len(esh)) + esh
    tg = (await uleb_encode(int(account_id)) + await uleb_encode(int(block_val)) +
          await uleb_encode(1) + await uleb_encode(int(mode_id)) +
          await uleb_encode(int(block_val)) + await uleb_encode(int(map_id)) + mid)
    process = await sv_frame(0x5E, match_code, 2, 447, 0, 1, garena420, udp_key)
    loading = await sv_frame(0x5A, match_code, 2, 448, 1, 1, tg, udp_key)
    return process.hex(), loading.hex()

async def classify(frame):
    cmd = frame["cmd"]
    name = MESSAGE_ID_TO_NAME.get(cmd, f"UNKNOWN_{cmd}")
    if name == "UDP_HELLO": return "HELLO"
    if name == "UDP_ACK": return "ACK"
    if name == "UDP_PING": return "PING"
    if name == "RUDP_JOIN_MATCH": return "JOIN_MATCH"
    if name.startswith("RUDP_"): return name
    if name.startswith("UDP_"): return name
    return "DATA"

async def reply_for(frame, key, mask, ack_key=0x68, ping_key=0x6D, hello_key=0x5B, ack_style="short"):
    _, nr = await layouts_from_mask(mask)
    typ = await classify(frame)
    if typ == "HELLO":
        if ack_style == "echo":
            content = frame["content"] if frame["content"] else b"\x10\x00\x00\x00"
            return typ, await build_packet(hello_key, nr, 1, 1, None, 1, content, key)
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x01\x00", key)
    if typ == "ACK":
        content = frame["content"] if frame["content"] else b"\x01\x00"
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, content, key)
    if typ == "PING":
        c = frame["content"]
        counter = c[:4] if len(c) >= 4 else c
        return typ, await build_packet(ping_key, nr, 0, 3, None, 0, counter + b"\x00\x00\x00", key, encrypted=False)
    if typ == "JOIN_MATCH":
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x02\x00", key)
    return typ, None

async def keepalive_ping(sock, ip, port, key_bytes, mask, stop_event):
    nr = (await layouts_from_mask(mask))[1]
    ping_keys = [0x66, 0x6D, 0x69, 0x6C, 0x6B, 0x6E, 0x6F, 0x70]
    loop = asyncio.get_event_loop(); i = 0
    while not stop_event.is_set():
        pk = ping_keys[i % len(ping_keys)]
        counter = int(time.time() * 1000) & 0xFFFFFFFF
        pkt = await build_packet(pk, nr, 0, 3, None, 0, struct.pack("<I", counter) + b"\x00\x00\x00",
                                 key_bytes, encrypted=False)
        try: await loop.sock_sendto(sock, pkt, (ip, port))
        except Exception: pass
        i += 1
        try: await asyncio.wait_for(stop_event.wait(), timeout=bypass_packet_jitter(3.0, 0.4))
        except asyncio.TimeoutError: pass

async def decode_packet(packet, key, mask=None):
    data = bytes(packet) if isinstance(packet, bytes) else bytes.fromhex(packet)
    if len(data) < 8: return None
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    crc_ok = (data[1] & 0x7F) == await crc7_buff(0, data[2:])
    candidates = []
    if mask:
        ru, nr = await layouts_from_mask(mask)
        layouts = [("RUDP", ru), ("nonRUDP", nr)]
    else:
        layouts = [("RUDP", list(p)) for p in itertools.permutations([0,1,2,3,4])]
        layouts += [("nonRUDP", list(p)) for p in itertools.permutations([0,1,3,4])]
    for kind, layout in layouts:
        off = 2; f = {}; ok = True
        for code in layout:
            size = _FIELD_SIZES[code]
            if off + size > len(data): ok = False; break
            f[_FIELD_NAMES[code]] = ((data[off] ^ k) if size == 1
                                    else ((data[off] | (data[off+1] << 8)) ^ v80) & 0xFFFF)
            off += size
        if not ok: continue
        if f["flags"] > 7 or f["sendOption"] > 7: continue
        if f["length"] != len(data) - off: continue
        body = data[off:off + f["length"]]
        content = None
        if f["flags"] & 1:
            if len(body) < 8 or len(body) % 8 != 0: continue
            content = await oicq_unpad(await tea_cbc_decrypt(body, key))
            if content is None: continue
        else: content = body
        score = (1 if crc_ok else 0) + (1 if content is not None else 0)
        candidates.append({"kind": kind, "layout": layout, "headerLen": off,
                          "msgKey": data[0], "cmd": f["cmd"], "flags": f["flags"],
                          "sendOption": f["sendOption"], "orderId": f.get("orderId"),
                          "length": f["length"], "content": content,
                          "crcOk": crc_ok, "score": score})
    if not candidates: return None
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[0]

# ═══════════════ NEW MOVEMENT (MoveState) ═══════════════
def read_varint_safe(data: bytes, offset: int) -> Tuple[int, int]:
    r, s = 0, 0
    while True:
        b = data[offset]
        offset += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, offset

def read_varints(buf):
    out = []
    off = 0
    while off < len(buf):
        v, off = read_varint_safe(buf, off)
        out.append(v)
    return out

def float_to_u32(f):
    return struct.unpack("<I", struct.pack("<f", float(f) + 0.0))[0]

class MoveState:
    def __init__(self):
        self.session_start = time.time()
        self.slot = None
        self.server_pos = None
        self.server_physx_state = None
        self.server_vel_y = 0
        self.server_update_seq = 0
        self.pending_ack = None
        self.rtt_ms = None
        self.ping_sent = {}
        self.cmd_counts = collections.Counter()
        self.undecoded = 0
        self.last_2001_head = None

    def diagnostics(self):
        top = ", ".join(f"{c}x{n}" for c, n in self.cmd_counts.most_common(12)) or "none"
        return (f"cmds [{top}] | undecoded {self.undecoded} | 2001 {self.server_update_seq} | slot {self.slot}")

    def on_server_frame(self, frame):
        self.cmd_counts[frame["cmd"]] += 1
        if frame.get("kind") == "RUDP" and frame.get("orderId") is not None:
            oid = frame["orderId"]
            if self.pending_ack is None or ((oid - self.pending_ack) & 0xFFFF) < 0x8000:
                self.pending_ack = oid
        if frame["cmd"] == MSG_PLAYER_STATE_SYNC:
            self._on_own_state(frame["content"] or b"")
        elif frame["cmd"] == 3:
            c = frame["content"] or b""
            if len(c) >= 4:
                sent = self.ping_sent.pop(struct.unpack_from("<I", c, 0)[0], None)
                if sent is not None:
                    self.rtt_ms = int((time.time() - sent) * 1000)

    def _on_own_state(self, content):
        try:
            v = read_varints(content)
        except Exception:
            self.last_2001_head = f"unparseable {content[:12].hex()}"
            return
        self.last_2001_head = v[:4]
        if len(v) < 16 or v[0] != 0 or v[1] != 2:
            return
        self.slot = v[2]
        self.server_pos = (zigzag_decode(v[3]), zigzag_decode(v[4]), zigzag_decode(v[5]))
        self.server_vel_y = zigzag_decode(v[12])
        self.server_physx_state = v[14]
        self.server_update_seq += 1

async def build_player_state_sync_2001(key_bytes, mask, msg_key, slot, pos, stick, move_input, vel,
                                       physx_state, physx_pose, facing, net_tick, counter_ms, ack_order=None):
    body = bytearray()
    body += await uleb_encode((1 << 24) | int(slot))
    for value in (*pos, *stick, *move_input, *vel):
        body += await zigzag_encode(int(round(value)))
    body += await uleb_encode(int(physx_state))
    body += await uleb_encode(int(physx_pose))
    for f in facing:
        body += await uleb_encode(float_to_u32(f))
    body += b"\x00\x00"
    body += await uleb_encode(int(net_tick))
    body += b"\x00\x00\x00"
    body += await uleb_encode(int(counter_ms))
    body = bytes(body)
    k = key_bytes[0]
    v80 = ((k << 8) | k) & 0xFFFF
    flags = 4 if ack_order is not None else 0
    nr = (await layouts_from_mask(mask))[1]
    hdr = bytearray([msg_key & 0xFF, 0])
    hdr += await encode_header(nr, 0, MSG_PLAYER_STATE_SYNC, None, flags, len(body), k, v80)
    if ack_order is not None:
        a = ((int(ack_order) & 0xFFFF) ^ v80) & 0xFFFF
        hdr += bytes([a & 0xFF, a >> 8, k])
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)

async def auto_move_loop(sock, ip, port, key_bytes, mask, state, stop_event, label=""):
    loop = asyncio.get_event_loop()

    async def wait(sec):
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=sec)
            return True
        except asyncio.TimeoutError:
            return False

    next_report = time.time() + AUTO_MOVE_SPAWN_TIMEOUT
    landed_deadline = None
    while True:
        if state.slot is not None and state.server_pos is not None:
            if landed_deadline is None:
                landed_deadline = time.time() + AUTO_MOVE_LAND_TIMEOUT
            if (state.server_physx_state == 0 and state.server_vel_y == 0) or time.time() > landed_deadline:
                break
        elif time.time() > next_report:
            _log(f"[MOVE]{label} waiting own-state: {state.diagnostics()}")
            next_report = time.time() + AUTO_MOVE_SPAWN_TIMEOUT
        if await wait(0.2):
            return
    if await wait(AUTO_MOVE_START_DELAY):
        return

    pos = list(state.server_pos)
    anchor = tuple(pos)
    seen_seq = state.server_update_seq
    heading = random.uniform(-math.pi, math.pi)
    stick = (math.sin(heading) * 100, 0.0, math.cos(heading) * 100)
    target = None
    speed = 0
    pause_until = time.time() + random.uniform(*AUTO_MOVE_PAUSE_RANGE)
    recent_sent = collections.deque(maxlen=40)
    last_send = time.time()
    print_success(f"[MOVE]{label} started (slot {state.slot})")

    while not stop_event.is_set():
        now = time.time()
        dt_ms = (now - last_send) * 1000.0
        last_send = now
        if state.server_update_seq != seen_seq and state.server_pos:
            seen_seq = state.server_update_seq
            sx, sy, sz = state.server_pos
            if recent_sent and all(math.hypot(sx - p[0], sz - p[2]) > AUTO_MOVE_RESYNC_DISTANCE for p in recent_sent):
                pos = [sx, sy, sz]
                anchor = (sx, sy, sz)
                target = None
                recent_sent.clear()
                pause_until = now + random.uniform(*AUTO_MOVE_PAUSE_RANGE)
        if target is None and now >= pause_until:
            for _ in range(10):
                ang = random.uniform(-math.pi, math.pi)
                dist = random.uniform(0, AUTO_MOVE_RADIUS)
                cand = (anchor[0] + math.sin(ang) * dist, anchor[2] + math.cos(ang) * dist)
                if math.hypot(cand[0] - pos[0], cand[1] - pos[2]) >= AUTO_MOVE_MIN_LEG:
                    break
            target = cand
            speed = AUTO_MOVE_RUN_SPEED if random.random() < AUTO_MOVE_RUN_CHANCE else AUTO_MOVE_WALK_SPEED
        move_input = (0, 0)
        vel = (0, 0, 0)
        pose = 0
        if target is not None:
            dx, dz = target[0] - pos[0], target[1] - pos[2]
            remaining = math.hypot(dx, dz)
            step = speed * dt_ms / 100.0
            if remaining <= step:
                pos[0], pos[2] = target
                target = None
                pause_until = now + random.uniform(*AUTO_MOVE_PAUSE_RANGE)
            else:
                want = math.atan2(dx, dz)
                diff = (want - heading + math.pi) % (2 * math.pi) - math.pi
                max_turn = math.radians(AUTO_MOVE_TURN_PER_TICK)
                heading += max(-max_turn, min(max_turn, diff))
                ux, uz = math.sin(heading), math.cos(heading)
                stick = (ux * 100, 0.0, uz * 100)
                move_input = (stick[0], stick[2])
                vel = (ux * speed, 0, uz * speed)
                pose = 2 if speed >= AUTO_MOVE_RUN_SPEED else 0
                pos[0] += ux * step
                pos[2] += uz * step
        facing = (math.sin(heading), 0.0, math.cos(heading))
        rtt = state.rtt_ms if state.rtt_ms is not None else AUTO_MOVE_DEFAULT_RTT
        ack = None
        if AUTO_MOVE_PIGGYBACK_ACK and state.pending_ack is not None:
            ack, state.pending_ack = state.pending_ack, None
        try:
            pkt = await build_player_state_sync_2001(
                key_bytes, mask, random.choice(AUTO_MOVE_MSG_KEYS), state.slot,
                pos, stick, move_input, vel, 0, pose, facing,
                max(1, min(1000, rtt)), int((now - state.session_start) * 1000), ack_order=ack)
            await loop.sock_sendto(sock, pkt, (ip, port))
            recent_sent.append((round(pos[0]), round(pos[1]), round(pos[2])))
        except Exception as e:
            _log(f"[MOVE]{label} send err: {e}")
        if await wait(AUTO_MOVE_TICK_INTERVAL):
            return

# ═══════════════ ANTI AFK ═══════════════
async def send_anti_afk_fire(sock, addr, udp_key_bytes, match_code, account_id):
    try:
        _, nr = await layouts_from_mask(match_code)
        try: pid = int(account_id)
        except Exception: pid = 0
        ts = int(time.time() * 1000) & 0xFFFFFFFF
        wid = random.choice([101, 102, 103, 201, 202])
        fire = struct.pack("<IIHB", pid & 0xFFFFFFFF, ts, wid, 1)
        fp = await build_packet(0x68, nr, 0, 104, None, 0, fire, udp_key_bytes, encrypted=False)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, fp, addr)
        await asyncio.sleep(bypass_jitter(random.uniform(0.15, 0.30), 0.05))
        stop = struct.pack("<IIHB", pid & 0xFFFFFFFF, ts + 200, wid, 0)
        sp = await build_packet(0x68, nr, 0, 105, None, 0, stop, udp_key_bytes, encrypted=False)
        await loop.sock_sendto(sock, sp, addr)
        return True
    except Exception: return False

async def anti_afk_worker(sock, ip, port, udp_key_bytes, match_code, account_id,
                          stop_event, match_index):
    addr = (ip, port)
    try:
        await asyncio.sleep(bypass_jitter(2.5, 0.5))
        while not stop_event.is_set():
            try:
                await send_anti_afk_fire(sock, addr, udp_key_bytes, match_code, account_id)
                w = random.uniform(ANTI_AFK_MIN_INTERVAL, ANTI_AFK_MAX_INTERVAL)
                w = bypass_packet_jitter(w, 0.25)
                try: await asyncio.wait_for(stop_event.wait(), timeout=w); break
                except asyncio.TimeoutError: pass
            except asyncio.CancelledError: break
            except Exception: await asyncio.sleep(1.0)
    except asyncio.CancelledError: pass

# ═══════════════ TEAM INVITE HANDLER ═══════════════
async def _handle_team_invite(hex_data, pl, uid_str, current_account_data,
                              current_key, current_iv, writer, grp: TeamGroup):
    try:
        candidates = []
        for off in [10, 8, 6, 12, 14, 4, 16, 0, 20, 2]:
            if off >= len(hex_data) or len(hex_data) - off < 4: continue
            try: inner = bytes.fromhex(hex_data[off:])
            except Exception: continue
            dec = decode_protobuf_dict(inner)
            if dec and isinstance(dec, dict) and len(dec) > 0:
                candidates.append((off, "parser", dec)); continue
            alt = _decode_proto_manual(inner)
            if alt and len(alt) > 0:
                candidates.append((off, "manual", {str(k): {"data": v} for k, v in alt.items()}))
        if not candidates: return False
        candidates.sort(key=lambda x: len(x[2]) if isinstance(x[2], dict) else 0, reverse=True)
        best_off, decoder, dec = candidates[0]

        def _unwrap(d, keys):
            if not isinstance(d, dict): return None
            for k in keys:
                v = d.get(k) if k in d else d.get(str(k))
                if isinstance(v, dict) and "data" in v: return v["data"]
                if isinstance(v, dict): return v
            return None

        target_dict = None
        for kp in [["5"], ["4"], ["6"], ["2"], ["1"]]:
            u = _unwrap(dec, kp)
            if isinstance(u, dict) and len(u) >= 3:
                target_dict = u; break
        if target_dict is None: target_dict = dec

        def _g(d, k):
            if not isinstance(d, dict): return None
            v = d.get(k) if k in d else d.get(str(k))
            if isinstance(v, dict) and "data" in v: return v["data"]
            if isinstance(v, dict):
                for kk in ["1","2","3","4","5","6","7","8"]:
                    vv = v.get(kk) if kk in v else v.get(int(kk))
                    if isinstance(vv, dict) and "data" in vv: return vv["data"]
            return v

        group_id = None
        for k in list(target_dict.keys()):
            c = _g(target_dict, k)
            if isinstance(c, str) and 20 <= len(c) <= 40:
                group_id = c; break
        if not group_id:
            for k in list(dec.keys()):
                c = _g(dec, k)
                if isinstance(c, str) and 20 <= len(c) <= 40:
                    group_id = c; break

        own_acc = str(current_account_data.get('account_id')) if current_account_data else None
        inviter = None
        all_f = list(target_dict.keys()) + list(dec.keys())
        for k in all_f:
            c = _g(target_dict, k) or _g(dec, k)
            if c and str(c).isdigit() and 6 <= len(str(c)) <= 15:
                if str(c) != uid_str and str(c) != own_acc:
                    inviter = str(c); break

        tc = None
        for k in all_f:
            c = _g(target_dict, k) or _g(dec, k)
            if c and str(c).isdigit() and len(str(c)) == 7:
                tc = str(c); break
        if tc:
            async with grp.lock:
                if grp.team_code != tc:
                    grp.team_code = tc
                    banner_team_code(tc, uid_str)

        is_member = (grp.leader_uid != uid_str)
        if inviter and group_id and is_member:
            async with grp.members_lock:
                already = uid_str in grp.members
            if already: return True
            accepted = False
            for attempt in range(3):
                try:
                    acc = accept_team_invite(int(inviter), group_id, current_key, current_iv)
                    if writer and not writer.is_closing():
                        writer.write(acc); await writer.drain()
                        accepted = True; break
                except Exception: pass
                await asyncio.sleep(0.8)
            if accepted:
                await team_member_join(grp, uid_str)
            return True
        return False
    except Exception: return False

# ═══════════════ PLAY GAME ═══════════════
async def play_game(server_ip_port, thunder, sharma, udp_key, match_code,
                    account_id, player_region, client_version, key, iv,
                    match_index, on_match_complete=None):
    t0 = time.time()
    ping_task = anti_task = move_task = None
    sock = None
    ping_stop = asyncio.Event(); anti_stop = asyncio.Event(); move_stop = asyncio.Event()
    uid_str = str(account_id); completed = False; died = False
    move_state = MoveState()
    # ═══ CHANGE 3: track last cmd=2001 (own-state sync) ═══
    last_2001_time = time.time()

    try:
        ip, port = server_ip_port.split(":"); port = int(port)
        rip = await resolve_host_cloudflare(ip)
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: sock.bind(('0.0.0.0', 0))
        except Exception: pass
        optimize_udp_socket(sock); sock.setblocking(False)
        udp_key_bytes = bytes.fromhex(udp_key)
        await asyncio.sleep(bypass_hello_delay())
        hello = await build_hello_packet(f"{account_id}_2585", udp_key_bytes, match_code)
        await loop.sock_sendto(sock, bytes.fromhex(hello), (rip, port))
        ack_state = "waiting_for_hello_reply"
        thunder_sent = False; join_match_rcv = False; local_closed = False
        send_lock = asyncio.Lock(); anti_started = False
        ping_task = asyncio.create_task(keepalive_ping(sock, rip, port, udp_key_bytes, match_code, ping_stop))
        last_activity = time.time()
        print_colored(f"[MATCH #{match_index}] UDP -> {server_ip_port}", Colors.MAGENTA)

        async def start_workers():
            nonlocal anti_task, move_task, anti_started
            if anti_started: return
            anti_started = True
            anti_task = asyncio.create_task(anti_afk_worker(sock, rip, port, udp_key_bytes, match_code,
                                                            account_id, anti_stop, match_index))

            async def delayed_movement():
                print_info(f"[MOVE] #{match_index} waiting {AUTO_MOVE_START_DELAY:.0f}s before movement...")
                try:
                    await asyncio.wait_for(move_stop.wait(), timeout=AUTO_MOVE_START_DELAY)
                    return
                except asyncio.TimeoutError:
                    pass
                if move_stop.is_set():
                    return
                await auto_move_loop(sock, rip, port, udp_key_bytes, match_code,
                                     move_state, move_stop, label=f"#{match_index}")

            if AUTO_MOVE_ENABLED:
                move_task = asyncio.create_task(delayed_movement())

        async def send_startup():
            nonlocal ack_state, thunder_sent
            if thunder_sent: return
            async with send_lock:
                if thunder_sent: return
                try:
                    await loop.sock_sendto(sock, bytes.fromhex(thunder), (rip, port))
                    thunder_sent = True
                    await asyncio.sleep(bypass_jitter(0.1, 0.05))
                    _, nr = await layouts_from_mask(match_code)
                    ack = await build_packet(0x68, nr, 0, 2, None, 1, b"\x01\x00", udp_key_bytes)
                    await loop.sock_sendto(sock, ack, (rip, port))
                    await asyncio.sleep(bypass_jitter(0.2, 0.05))
                    await loop.sock_sendto(sock, bytes.fromhex(sharma), (rip, port))
                    ack_state = "thunder_sharma_sent"
                    print_success(f"[MATCH #{match_index}] Startup delivered")
                    await start_workers()
                except Exception as e: print_error(f"[MATCH #{match_index}] startup: {e}")

        while not local_closed:
            if time.time() - t0 > MAX_MATCH_DURATION:
                completed = True; break
            if ack_state != "thunder_sharma_sent" and (time.time() - t0) > HANDSHAKE_TIMEOUT:
                print_warning(f"[MATCH #{match_index}] Handshake timeout")
                break
            try:
                resp, saddr = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout=1.5)
                if resp:
                    frame = await decode_packet(resp, udp_key_bytes, match_code)
                    if frame:
                        try: move_state.on_server_frame(frame)
                        except Exception: pass

                        pt = await classify(frame)

                        # ═══ CHANGE 3a: only real packets count as activity ═══
                        if pt not in ("PING", "ACK"):
                            last_activity = time.time()

                        # ═══ CHANGE 3b: track cmd=2001 ═══
                        if frame['cmd'] == 2001:
                            last_2001_time = time.time()

                        if frame['cmd'] in [103, 107]:
                            if not died:
                                print_warning(f"[MATCH #{match_index}] Died/Ended cmd={frame['cmd']}")
                                died = True; completed = True
                                move_stop.set(); anti_stop.set()
                            local_closed = True; continue

                        if frame['cmd'] == 101:
                            try:
                                _, nr = await layouts_from_mask(match_code)
                                a = await build_packet(0x68, nr, 0, 2, None, 1, b"\x01\x00", udp_key_bytes)
                                await loop.sock_sendto(sock, a, saddr)
                            except Exception: pass
                            continue
                        if pt in ["ACK", "PING", "HELLO", "JOIN_MATCH"]:
                            if pt == "HELLO" and ack_state == "waiting_for_hello_reply":
                                _, r = await reply_for(frame, udp_key_bytes, match_code, ack_style="short")
                                if r: await loop.sock_sendto(sock, r, saddr)
                                ack_state = "ack_sent_waiting"
                            elif pt == "ACK":
                                if ack_state == "waiting_for_hello_reply":
                                    _, r = await reply_for(frame, udp_key_bytes, match_code)
                                    if r: await loop.sock_sendto(sock, r, saddr)
                                    ack_state = "ready_to_send_thunder"
                                elif ack_state == "ack_sent_waiting":
                                    ack_state = "ready_to_send_thunder"
                                else:
                                    _, r = await reply_for(frame, udp_key_bytes, match_code)
                                    if r: await loop.sock_sendto(sock, r, saddr)
                            elif pt == "PING":
                                _, r = await reply_for(frame, udp_key_bytes, match_code)
                                if r: await loop.sock_sendto(sock, r, saddr)
                            elif pt == "JOIN_MATCH" and not join_match_rcv:
                                _, r = await reply_for(frame, udp_key_bytes, match_code)
                                if r: await loop.sock_sendto(sock, r, saddr); join_match_rcv = True
            except asyncio.TimeoutError:
                if ack_state == "ready_to_send_thunder" and not thunder_sent:
                    await send_startup()
                elif ack_state == "waiting_for_hello_reply":
                    if (time.time() - last_activity) > 7.0:
                        try:
                            hp = await build_hello_packet(f"{account_id}_2585", udp_key_bytes, match_code)
                            await loop.sock_sendto(sock, bytes.fromhex(hp), (rip, port))
                        except Exception: pass
                        last_activity = time.time()
                elif ack_state == "thunder_sharma_sent":
                    # ═══ CHANGE 3c: match end detection ═══
                    # 1) 30s idle (no real packets — keepalive ignored)
                    if (time.time() - last_activity) > MATCH_IDLE_TIMEOUT:
                        print_success(f"[MATCH #{match_index}] Idle timeout ({MATCH_IDLE_TIMEOUT:.0f}s) → match ended")
                        completed = True; break
                    # 2) 45s no cmd=2001 → player out of map / match ended
                    if (time.time() - last_2001_time) > 45.0:
                        print_success(f"[MATCH #{match_index}] No own-state 45s → match ended")
                        completed = True; break
                continue
            except BlockingIOError: await asyncio.sleep(0.05)
            except OSError: await asyncio.sleep(0.5); continue
            except Exception: await asyncio.sleep(0.5); continue
            if ack_state == "ready_to_send_thunder" and not thunder_sent:
                try: await send_startup()
                except Exception: pass
        return f"match #{match_index} finished"
    except Exception as e:
        print_error(f"[MATCH #{match_index}] {e}"); return f"match #{match_index} error"
    finally:
        if completed and on_match_complete:
            try: asyncio.create_task(on_match_complete())
            except Exception: pass
        anti_stop.set(); move_stop.set()
        for t in (anti_task, move_task):
            if t:
                try: await asyncio.wait_for(t, timeout=2.0)
                except Exception:
                    t.cancel()
                    try: await t
                    except Exception: pass
        ping_stop.set()
        if ping_task:
            ping_task.cancel()
            try: await ping_task
            except asyncio.CancelledError: pass
        if sock:
            try: sock.close()
            except Exception: pass
        rem = await _dec_match(uid_str)
        print_info(f"[MATCH #{match_index}] Closed. UID:{rem}")

# ═══════════════ FUNCTIONAL BATTLE ROYALE ═══════════════
async def functional_battle_royale(addrs, starter_packet, account_region, client_version,
                                    key, iv, account_id="", account_data=None,
                                    account_level=2, max_reconnects=10,
                                    grp: Optional[TeamGroup] = None):
    if grp is None:
        grp = TeamGroup(0, TEAM_SIZE)
    if not addrs or ":" not in str(addrs):
        print_error(f"[FUNC] Missing TCP address for {account_id}")
        return

    reconnects = 0
    ip, port = addrs.split(":")
    no_response_count = 0
    uid_str = str(account_id)
    current_level = int(account_level or 2)
    current_token = starter_packet
    current_key = key; current_iv = iv
    current_account_data = account_data
    reconnect_count_total = 0
    region_index = 0
    current_search_region = account_region or REGION_ROTATION_LIST[0]
    _writer_ref = {"w": None}
    current_match_task: Optional[asyncio.Task] = None

    async def trigger_post_match_refresh():
        await asyncio.sleep(EXP_REFRESH_AFTER_MATCH_DELAY)
        print_info(f"[EXP] post-match refresh for {uid_str}")

    async def _team_coordinator():
        try:
            deadline = time.time() + TEAM_PEER_WAIT_TIMEOUT
            min_ok = max(2, grp.size - 1)
            while time.time() < deadline:
                async with grp.lock:
                    n = len(grp.peers)
                if n >= grp.size: break
                if n >= min_ok:
                    await asyncio.sleep(1.5)
                    async with grp.lock:
                        n2 = len(grp.peers)
                    if n2 >= min_ok: break
                await asyncio.sleep(0.3)

            async with grp.lock:
                is_leader = (grp.leader_uid == uid_str)
                peers_snapshot = dict(grp.peers)

            if not is_leader: return

            await asyncio.sleep(TEAM_READY_DELAY)
            print_success(f"[TEAM-{grp.tag()}] 👑 {uid_str} creating squad...")

            async with grp.lock:
                grp.team_code = None
                grp.pk_code = None

            own_id_num = None
            if current_account_data: own_id_num = current_account_data.get('account_id')
            if not own_id_num:
                try: own_id_num = int(uid_str)
                except Exception: own_id_num = 0

            try:
                pkt = create_team(current_key, current_iv, client_version)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
                    await team_member_reset(grp, keep_leader=False)
                    await team_member_join(grp, uid_str)
                    print_info(f"[TEAM-{grp.tag()}] create_team sent ({len(pkt)}B)")
            except Exception as e:
                print_error(f"[TEAM-{grp.tag()}] create_team: {e}")

            await asyncio.sleep(TEAM_CREATE_WAIT)

            for _ in range(20):
                if grp.team_code:
                    break
                await asyncio.sleep(0.5)
            if grp.team_code:
                banner_team_code(grp.team_code, uid_str)
            else:
                print_warning(f"[TEAM-{grp.tag()}] Team code not yet received after 10s")

            peer_uids = []
            for peer_uid, info in peers_snapshot.items():
                if peer_uid == uid_str: continue
                pa = None
                try: pa = info["data"].get("account_id")
                except Exception: pass
                if not pa: pa = peer_uid
                peer_uids.append(int(pa))

            heartbeat_stop = asyncio.Event()
            async def heartbeat_loop():
                while not heartbeat_stop.is_set():
                    try:
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            pkt = team_fresh(int(own_id_num), current_key, current_iv)
                            _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
                    except Exception: pass
                    try: await asyncio.wait_for(heartbeat_stop.wait(), timeout=TEAM_HEARTBEAT_INTERVAL)
                    except asyncio.TimeoutError: pass
            hb_task = asyncio.create_task(heartbeat_loop())

            invite_start = time.time()
            while time.time() - invite_start < TEAM_INVITE_MAX_TIME:
                if not grp.active["flag"]: break
                cnt = await team_member_count(grp)
                if cnt >= grp.size: break
                for tuid in peer_uids:
                    async with grp.members_lock:
                        joined = str(tuid) in grp.members
                    if joined: continue
                    try:
                        inv = invite_player_in_team(tuid, current_key, current_iv, region=account_region)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(inv); await _writer_ref["w"].drain()
                    except Exception: pass
                    await asyncio.sleep(0.5)
                try: await asyncio.wait_for(heartbeat_stop.wait(), timeout=TEAM_INVITE_CYCLE_WAIT)
                except asyncio.TimeoutError: pass

            final_cnt = await team_member_count(grp)
            if final_cnt < grp.size:
                heartbeat_stop.set()
                try: hb_task.cancel(); await hb_task
                except Exception: pass
                return

            await asyncio.sleep(TEAM_FINAL_WAIT)
            heartbeat_stop.set()
            try: hb_task.cancel(); await hb_task
            except Exception: pass

            while grp.active["flag"]:
                try:
                    async with grp.lock:
                        if grp.leader_uid != uid_str: break
                    oid = current_account_data.get('account_id', own_id_num) if current_account_data else own_id_num
                    try:
                        rdy = ready_for_game(int(oid), current_key, current_iv)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                    except Exception: pass
                    await asyncio.sleep(1.0)
                    sm = start_match_team(int(oid), current_key, current_iv, region=account_region)
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception: pass
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception as e:
            print_error(f"[TEAM-{grp.tag()}] coordinator: {e}")

    async def _member_match_trigger():
        try:
            await asyncio.sleep(TEAM_READY_DELAY + TEAM_MEMBER_START_DELAY)
            async with grp.lock:
                if grp.leader_uid == uid_str: return
            my_id = current_account_data.get('account_id', uid_str) if current_account_data else uid_str
            while grp.active["flag"]:
                try:
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        try:
                            rdy = ready_for_game(int(my_id), current_key, current_iv)
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                        except Exception: pass
                        await asyncio.sleep(1.0)
                        sm = start_match_team(int(my_id), current_key, current_iv, region=account_region)
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception: pass
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception: pass

    try:
        while True:
            writer = None; gateway_ping_task = None
            team_coord_task = None; member_trigger_task = None
            try:
                rip = await resolve_host_cloudflare(ip)
                reader, writer = await asyncio.open_connection(rip, int(port))
                _writer_ref["w"] = writer
                raw_sock = writer.get_extra_info('socket')
                if raw_sock: optimize_tcp_socket(raw_sock)
                await asyncio.sleep(bypass_hello_delay())
                writer.write(bytes.fromhex(current_token)); await writer.drain()
                try:
                    ka = await send_keep_alive(account_region)
                    if ka and not writer.is_closing():
                        writer.write(ka); await asyncio.wait_for(writer.drain(), timeout=3)
                except Exception: pass

                async def func_gateway_keepalive():
                    ka_bytes = await send_keep_alive(account_region)
                    while True:
                        await asyncio.sleep(bypass_ka_jitter(5.0))
                        try:
                            if writer and not writer.is_closing():
                                writer.write(ka_bytes); await writer.drain()
                        except Exception: break
                gateway_ping_task = asyncio.create_task(func_gateway_keepalive())

                connection_start_time = asyncio.get_running_loop().time()
                last_watchdog_check = connection_start_time
                search_attempts = 0
                if reconnect_count_total > 0 and (reconnect_count_total % REGION_ROTATE_EVERY_N == 0):
                    region_index = (region_index + 1) % len(REGION_ROTATION_LIST)
                    current_search_region = REGION_ROTATION_LIST[region_index]
                else:
                    current_search_region = account_region or REGION_ROTATION_LIST[region_index]

                print_success(f"[FUNC-{grp.tag()}] TCP connected {uid_str} (DNS:{rip} Lvl:{current_level})")
                reconnects = 0; no_response_count = 0

                async with grp.lock:
                    grp.peers[uid_str] = {
                        "writer": writer, "data": current_account_data,
                        "key": current_key, "iv": current_iv}
                    if grp.leader_uid is None:
                        grp.leader_uid = uid_str
                        print_success(f"[TEAM-{grp.tag()}] 👑 {uid_str} is leader")

                if TEAM_MODE:
                    team_coord_task = asyncio.create_task(_team_coordinator())
                    member_trigger_task = asyncio.create_task(_member_match_trigger())
                else:
                    await start_game_battle_royale(current_search_region, client_version,
                                                   writer, current_key, current_iv)

                while True:
                    active = 1 if (current_match_task and not current_match_task.done()) else 0

                    now = asyncio.get_running_loop().time()
                    if now - last_watchdog_check >= MATCH_WATCHDOG_CHECK:
                        last_watchdog_check = now
                        sd = now - connection_start_time
                        if sd > MATCH_SEARCH_TIMEOUT:
                            if active > 0:
                                connection_start_time = now
                            else:
                                raise ConnectionError("Search watchdog")
                    if search_attempts >= MAX_SEARCH_ATTEMPTS:
                        raise ConnectionError("Max attempts")

                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=0.5)
                    except asyncio.TimeoutError:
                        no_response_count += 1
                        if TEAM_MODE:
                            if no_response_count > TEAM_IDLE_ITERS_TEAM:
                                raise ConnectionError("Team idle timeout")
                        else:
                            if no_response_count > 80: raise ConnectionError("idle")
                        continue

                    if not data: raise ConnectionError("closed")
                    hex_data = data.hex()
                    pl = len(data)
                    no_response_count = 0

                    try:
                        tc = extract_team_code_from_bytes(data)
                        if tc:
                            async with grp.lock:
                                if grp.team_code != tc:
                                    grp.team_code = tc
                                    should_banner = True
                                else:
                                    should_banner = False
                            if should_banner:
                                banner_team_code(tc, uid_str)
                    except Exception: pass

                    if hex_data.startswith("05") and pl > 10:
                        await _handle_team_invite(hex_data, pl, uid_str, current_account_data,
                                                  current_key, current_iv, writer, grp)
                        continue

                    if hex_data.startswith("0300") and 10 < pl < 30:
                        continue

                    if hex_data.startswith("0300") and pl >= 300:
                        print_colored("=" * 60, Colors.GREEN)
                        print_colored("MATCH FOUND! Loading...", Colors.GREEN)
                        print_colored("=" * 60, Colors.GREEN)

                        for tk in (team_coord_task, member_trigger_task):
                            if tk and not tk.done():
                                tk.cancel()
                                try: await tk
                                except asyncio.CancelledError: pass
                        team_coord_task = None; member_trigger_task = None
                        grp.active["flag"] = False

                        try:
                            res = json.loads(await decode_protobuf(hex_data[10:]))
                            token = udp_key = match_code = server_ip_port = None
                            match_account_id = block_val = None

                            if '42' in res and 'data' in res['42']:
                                match_code = res['42']['data']
                            if '2' in res and 'data' in res['2'] and isinstance(res['2']['data'], str):
                                server_ip_port = res['2']['data']
                            if '3' in res and 'data' in res['3']:
                                udp_key = res['3']['data']
                            if '4' in res and 'data' in res['4']:
                                token = res['4']['data']
                            if '1' in res and 'data' in res['1']:
                                match_account_id = res['1']['data']

                            if '5' in res and 'data' in res['5'] and isinstance(res['5']['data'], dict):
                                r5 = res['5']['data']
                                server_ip_port = r5.get('2', {}).get('data') or server_ip_port
                                udp_key = r5.get('3', {}).get('data') or udp_key
                                token = r5.get('4', {}).get('data') or token
                                if '42' in r5: match_code = r5['42']['data']
                                block_val = r5.get('1', {}).get('data') or block_val

                            print_info(f"[MATCH-DATA] server={server_ip_port} udp_key={str(udp_key)[:16]}... mcode={match_code}")

                            effective = match_account_id or account_id or "BD_BOT"
                            if token and udp_key and match_code and server_ip_port:
                                acc_tok = current_account_data.get('access_token', '') if current_account_data else ""
                                thunder, sharma = await build_match_startup_packets(
                                    token, udp_key, match_code, effective, block_val or 0,
                                    server_ip=server_ip_port, region=account_region,
                                    client_version=client_version, access_token=acc_tok,
                                    mode_id=BR_MODE_ID, map_id=BR_MAP_ID)

                                try:
                                    _uid_num = None
                                    if current_account_data:
                                        _uid_num = current_account_data.get('uid') or \
                                                   current_account_data.get('auth_uid') or \
                                                   current_account_data.get('open_id')
                                    _uid_num = int(_uid_num) if _uid_num else int(effective)
                                    _name = (current_account_data or {}).get('nickname', f"Player_{_uid_num}")
                                    _acc_id = int(effective)
                                    sm_pkt = build_start_match_v2(
                                        _acc_id, _uid_num, _name, server_ip_port, udp_key,
                                        token, match_code=str(match_code), region=account_region,
                                        key=current_key, iv=current_iv, framed=True)
                                    if writer and not writer.is_closing():
                                        writer.write(sm_pkt); await writer.drain()
                                        print_success(f"[START-MATCH] sent {len(sm_pkt)}B uid={_uid_num}")
                                except Exception as _e:
                                    print_warning(f"[START-MATCH] {_e}")

                                match_index = await _inc_match(uid_str)
                                print_colored(f"[MATCH #{match_index}] UDP -> {server_ip_port} (sequential)", Colors.CYAN)

                                current_match_task = asyncio.create_task(play_game(
                                    server_ip_port, thunder, sharma, udp_key, match_code,
                                    effective, current_search_region, client_version,
                                    current_key, current_iv,
                                    match_index=match_index,
                                    on_match_complete=trigger_post_match_refresh))

                                await team_member_leave(grp, uid_str)
                                await team_member_reset(grp, keep_leader=False)
                                async with grp.lock:
                                    grp.pk_code = None
                                    grp.team_code = None
                                    grp.peers[uid_str] = {
                                        "writer": writer,
                                        "data": current_account_data,
                                        "key": current_key, "iv": current_iv}
                                    if not grp.leader_uid:
                                        grp.leader_uid = uid_str

                                print_info(f"[MATCH #{match_index}] waiting for match to end...")
                                try:
                                    await current_match_task
                                except Exception as e:
                                    print_error(f"[MATCH #{match_index}] crashed: {e}")
                                current_match_task = None

                                print_success(f"[MATCH #{match_index}] ended. Closing TCP → offline → next round re-login.")
                                await asyncio.sleep(AFTER_MATCH_COOLDOWN)

                                return
                            else:
                                print_warning(f"[FUNC-{grp.tag()}] missing fields")
                                await safe_close_writer(writer)
                                await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                                break
                        except Exception as e:
                            print_error(f"[FUNC-{grp.tag()}] Match parse: {e}")
                            traceback.print_exc()
                            await safe_close_writer(writer)
                            await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                            break

                    if 30 <= pl <= 40: continue

            except asyncio.CancelledError:
                if current_match_task and not current_match_task.done():
                    current_match_task.cancel()
                    try: await current_match_task
                    except Exception: pass
                current_match_task = None
                if gateway_ping_task: gateway_ping_task.cancel()
                async with grp.lock:
                    grp.peers.pop(uid_str, None)
                    if grp.leader_uid == uid_str:
                        grp.leader_uid = None
                await team_member_leave(grp, uid_str)
                raise
            except Exception as e:
                if gateway_ping_task: gateway_ping_task.cancel()
                print_error(f"[FUNC-{grp.tag()}] TCP state {uid_str}: {e}")
                await safe_close_writer(writer)
                reconnect_count_total += 1
                reconnects += 1
                if reconnects > max_reconnects:
                    reconnects = 0
                    await asyncio.sleep(3)
                    continue
                await asyncio.sleep(bypass_human_reconnect_delay(reconnects))
            finally:
                grp.active["flag"] = False
                for tk in (team_coord_task, member_trigger_task):
                    if tk and not tk.done():
                        tk.cancel()
                        try: await tk
                        except (asyncio.CancelledError, Exception): pass
                if gateway_ping_task: gateway_ping_task.cancel()
                await safe_close_writer(writer)
                async with grp.lock:
                    grp.peers.pop(uid_str, None)
                    if grp.leader_uid == uid_str:
                        grp.leader_uid = None
                await team_member_leave(grp, uid_str)
                grp.active["flag"] = True
    except asyncio.CancelledError:
        if current_match_task and not current_match_task.done():
            current_match_task.cancel()
        raise

# ═══════════════ ACCOUNT WORKER ═══════════════
async def account_loop_guest(uid, password, grp: TeamGroup,
                             region_override=None):
    uid = str(uid)
    while True:
        try:
            print_info(f"[LOGIN] {uid}...")
            ad = await login_via_core(uid, password, region_override)
            print_success(f"[OK] {ad['account_id']} | {ad['nickname']} | R={ad['region']}")

            reg = ad['region']
            tcp_online = await build_tcp_startup_packet(
                ad['account_id'], ad['token'], ad['server_time'],
                ad['aes_ak'], ad['iv_i'], region=reg, typ='OnLine')

            ping_stop = asyncio.Event()
            try:
                _phost = str(ad.get("server_url") or PING_URL).rstrip("/")
                _purl = _phost if _phost.endswith("/Ping") else (_phost + "/Ping")
                ping_task = asyncio.create_task(ping_worker(
                    ad['account_id'], ad['token'], ad.get('release_version') or "OB55",
                    region=reg, ping_url=_purl, stop_event=ping_stop))
            except Exception:
                ping_task = None

            try:
                while True:
                    try:
                        await functional_battle_royale(
                            ad['game_server'], tcp_online, reg,
                            ad.get('client_version') or FORCED_CLIENT_VERSION,
                            ad['aes_ak'], ad['iv_i'], account_id=ad['account_id'],
                            account_data=ad, account_level=1, grp=grp)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        print_error(f"[RETRY] {uid}: {e}")
                        traceback.print_exc()

                    print_warning(f"[RETRY] {uid} session ended, restart {SESSION_RETRY_DELAY}s")
                    await asyncio.sleep(SESSION_RETRY_DELAY)
                    try:
                        ad = await login_via_core(uid, password, region_override)
                        reg = ad['region']
                        tcp_online = await build_tcp_startup_packet(
                            ad['account_id'], ad['token'], ad['server_time'],
                            ad['aes_ak'], ad['iv_i'], region=reg, typ='OnLine')
                        print_success(f"[RE-LOGIN] {uid} → fresh TCP ready")
                    except Exception as e:
                        print_error(f"[RELOGIN] {uid}: {e}")
                        break
            finally:
                ping_stop.set()
                if ping_task:
                    ping_task.cancel()
                    try: await ping_task
                    except asyncio.CancelledError: pass
        except asyncio.CancelledError:
            break
        except Exception as e:
            print_error(f"[LOGIN-ERR] {uid}: {e}, retry 15s")
            traceback.print_exc()
            await asyncio.sleep(15)

# ═══════════════ LOAD / GROUPS ═══════════════
def make_squad_groups(accounts: List[dict]) -> List[Tuple[TeamGroup, List[dict]]]:
    groups = []
    for gi, i in enumerate(range(0, len(accounts), TEAM_SIZE)):
        chunk = accounts[i:i + TEAM_SIZE]
        grp = TeamGroup(gi, size=len(chunk))
        groups.append((grp, chunk))
    return groups

# ═══════════════ INTERACTIVE ENTRY ═══════════════
async def start_match_interactive():
    _load_login_cache_file()

    accounts = load_squad_accounts()
    if not accounts:
        print_error("No accounts found in squad_accounts.json")
        return

    print_success(f"[BOOT] {len(accounts)} account(s) loaded from squad_accounts.json")

    print(f"\n  Choose Match Region:")
    row = []
    for i, r in enumerate(REGION_LIST, 1):
        row.append(f"{i:>2}. {r}")
        if i % 3 == 0:
            print(f"      " + "      ".join(row))
            row = []
    if row:
        print(f"      " + "      ".join(row))

    try:
        raw = input("  > ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        return

    if raw.isdigit() and 1 <= int(raw) <= len(REGION_LIST):
        region_hint = REGION_LIST[int(raw) - 1]
    elif raw in REGION_LIST:
        region_hint = raw
    else:
        region_hint = None

    print(f"\n  Starting match in region: {region_hint or 'auto'}\n")

    squads = make_squad_groups(accounts)
    print_success(f"[SQUAD] {len(accounts)} account(s) -> {len(squads)} squad(s)")

    tasks = []
    for grp, chunk in squads:
        for acc in chunk:
            uid = str(acc.get("uid") or "").strip()
            password = acc.get("pass") or acc.get("password")
            if not uid or not password:
                continue
            region_override = region_hint or acc.get("region")
            task = asyncio.create_task(
                account_loop_guest(uid, password, grp, region_override))
            tasks.append(task)
            await asyncio.sleep(0.4)

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except (KeyboardInterrupt, asyncio.CancelledError):
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            global _aiohttp_session
            if _aiohttp_session is not None and not _aiohttp_session.closed:
                await _aiohttp_session.close()
                _aiohttp_session = None
        except Exception:
            pass
        print_info("[CLEANUP] All connections closed.")


if __name__ == "__main__":
    try:
        asyncio.run(start_match_interactive())
    except KeyboardInterrupt:
        print_warning("stopped")