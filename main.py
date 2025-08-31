import os, sys, time, json, base64, secrets, asyncio, random, math, sqlite3, threading, gc, textwrap, stat, platform, re
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except Exception as e:
    print(f"Missing dependency: psutil ({e})"); sys.exit(1)
try:
    import httpx
except Exception as e:
    print(f"Missing dependency: httpx ({e})"); sys.exit(1)
try:
    import bleach
except Exception as e:
    print(f"Missing dependency: bleach ({e})"); sys.exit(1)
try:
    from jsonschema import Draft7Validator, ValidationError
except Exception as e:
    print(f"Missing dependency: jsonschema ({e})"); sys.exit(1)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except Exception as e:
    print(f"Missing dependency: cryptography ({e})"); sys.exit(1)
try:
    import getpass
except Exception as e:
    print(f"Missing dependency: getpass ({e})"); sys.exit(1)

IS_WINDOWS = platform.system().lower().startswith("win")

try:
    import oqs
    HAVE_OQS = True
except Exception:
    HAVE_OQS = False
if not HAVE_OQS:
    print("[FATAL] liboqs not available. Aborting."); sys.exit(1)

try:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("[WARN] Running as root. Not recommended for alert-only mode.")
except Exception:
    pass
try:
    if not IS_WINDOWS:
        os.umask(0o077)
except Exception:
    pass

try:
    import winsound
except Exception:
    winsound = None

def _die(msg: str):
    print(msg); sys.exit(1)

KEM_ALG = os.getenv("HYPERTIME_OQS_ALG", "Kyber768")
SIG_ALG = os.getenv("HYPERTIME_OQS_SIG", "Dilithium3")
try:
    if KEM_ALG not in oqs.get_enabled_kem_mechanisms():
        _die(f"[FATAL] OQS KEM '{KEM_ALG}' not available.")
    if SIG_ALG not in oqs.get_enabled_sig_mechanisms():
        _die(f"[FATAL] OQS SIG '{SIG_ALG}' not available.")
except Exception as e:
    _die(f"[FATAL] OQS mechanisms query failed: {e}")

OPENAI_MODEL = os.getenv("HYPERTIME_MODEL", "gpt-4o")
API_BASE = os.getenv("OPENAI_API_BASE", "https://api.openai.com")
ALERT_ON_ANY_ACTION = os.getenv("HYPERTIME_ALERT_ON_ACTION", "1") == "1"
BEEP_SECONDS = max(0, int(os.getenv("HYPERTIME_BEEP_SECONDS", "15") or "15"))
BASE_MIN = 35.0
BASE_MAX = 293.0
QID25_COLORS = ["RED", "YELLOW", "BLUE", "GREEN"]
COLOR_MULT = {"RED": 0.35, "YELLOW": 0.60, "BLUE": 0.90, "GREEN": 1.15}

if IS_WINDOWS:
    DEFAULT_DB = os.path.expanduser(os.getenv("HYPERTIME_DB", r"~\AppData\Local\Hypertime\hypertime.db"))
else:
    DEFAULT_DB = os.path.expanduser(os.getenv("HYPERTIME_DB", "~/.local/state/hypertime/hypertime.db"))
os.makedirs(os.path.dirname(DEFAULT_DB), exist_ok=True)

AAD_LOG = b"hypertime-ids-v6/log-v2"
AAD_SECRET = b"hypertime-ids-v6/keystore-v2"
AAD_LOG_META = b"hypertime-ids-v6/logmeta-v1"

def _secure_touch_0600(path: str):
    flags = os.O_CREAT | os.O_RDWR
    try:
        fd = os.open(path, flags, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    try:
        st = os.stat(path)
        if stat.S_ISREG(st.st_mode):
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
    except Exception:
        pass

HAVE_ARGON2 = False
ARGON2_OK = False
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    HAVE_ARGON2 = True
except Exception:
    HAVE_ARGON2 = False
import hashlib

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

DEFAULT_SCRYPT_MAXMEM = _env_int("HYPERTIME_SCRYPT_MAXMEM", 256 * 1024 * 1024)

def _scrypt_safe(data: bytes, salt: bytes, dklen: int = 32, n: int = 2**15, r: int = 8, p: int = 2, maxmem: Optional[int] = None) -> bytes:
    if maxmem is None:
        maxmem = DEFAULT_SCRYPT_MAXMEM
    n_candidates = [n, 2**14, 2**13, 2**12]
    last_err = None
    for n_try in n_candidates:
        try:
            return hashlib.scrypt(data, salt=salt, n=n_try, r=r, p=p, maxmem=maxmem, dklen=dklen)
        except ValueError as e:
            last_err = e
            continue
    for r_try in [4, 2]:
        try:
            return hashlib.scrypt(data, salt=salt, n=2**12, r=r_try, p=p, maxmem=maxmem, dklen=dklen)
        except ValueError as e:
            last_err = e
            continue
    raise last_err  # type: ignore[name-defined]

def _argon2_derive_or_none(data: bytes, salt: bytes, length: int, t: int, m: int, p: int):
    if not HAVE_ARGON2:
        return None
    try:
        kdf = Argon2id(time_cost=t, memory_cost=m, parallelism=p, length=length, salt=salt)
    except TypeError:
        try:
            kdf = Argon2id(m, t, p, length, salt)  # type: ignore
        except Exception:
            return None
    try:
        return kdf.derive(data)
    except Exception:
        return None

def current_kdf_label() -> str:
    return "argon2id" if ARGON2_OK else "scrypt"

def _oqs_hybrid_secret() -> bytes:
    mode = os.getenv("HYPERTIME_OQS_MODE", "self").lower()
    if mode not in ("self","encap"):
        _die("[FATAL] HYPERTIME_OQS_MODE must be 'self' or 'encap'.")
    try:
        if mode == "encap":
            pub_b64 = os.getenv("HYPERTIME_OQS_PUBKEY_B64", "")
            if not pub_b64:
                _die("[FATAL] OQS encap mode requires HYPERTIME_OQS_PUBKEY_B64.")
            pub = base64.b64decode(pub_b64.strip())
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                _, ss = kem.encap_secret(pub)
                return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hypertime-ids/boot/oqs-encap").derive(ss)
        else:
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                pub = kem.generate_keypair()
                ct, ss = kem.encap_secret(pub)
                try:
                    _ = kem.decap_secret(ct)
                except Exception:
                    pass
                return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hypertime-ids/boot/oqs-self").derive(ss)
    except Exception as e:
        _die(f"[FATAL] OQS operation failed: {e}")

def derive_boot_key() -> bytes:
    global ARGON2_OK
    seed = secrets.token_bytes(32)
    salt1 = secrets.token_bytes(16)
    base_key = _argon2_derive_or_none(seed, salt1, length=32, t=4, m=2**15, p=2)
    if base_key is not None:
        ARGON2_OK = True
    else:
        ARGON2_OK = False
        base_key = _scrypt_safe(seed, salt1, dklen=32)
    oqs_key = _oqs_hybrid_secret()
    if not oqs_key:
        _die("[FATAL] PQ boot secret missing.")
    salt2 = secrets.token_bytes(16)
    ikm = base_key + oqs_key + secrets.token_bytes(32)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt2, info=b"hypertime-ids/hybrid/v2").derive(ikm)
    os.environ["HYPERTIME_OQS_ENABLED"] = "1"
    return key

def _hkdf_key(master: bytes, salt: bytes, info: bytes, ln: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=ln, salt=salt, info=info).derive(master)

def encrypt_log_envelope(obj: dict, boot_key: bytes, ts: int, meta: Dict[str, Any], signer: "PQSigner") -> Dict[str, str]:
    salt = secrets.token_bytes(16)
    per_key = _hkdf_key(boot_key, salt, b"hypertime-ids/log-key/v2")
    nonce = secrets.token_bytes(12)
    aad = AAD_LOG + json.dumps({"ts": ts, "m": meta}, separators=(",", ":"), ensure_ascii=False).encode()
    ct = AESGCM(per_key).encrypt(nonce, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), aad)
    blob = salt + nonce + ct
    sig = signer.sign(blob + aad + AAD_LOG_META)
    return {
        "cipher_b64": base64.b64encode(blob).decode(),
        "sig_b64": base64.b64encode(sig).decode(),
        "sig_pub_b64": base64.b64encode(signer.pub).decode(),
        "sig_alg": signer.alg,
    }

def decrypt_log_envelope(b64: str, boot_key: bytes, ts: int, meta: Dict[str, Any]) -> dict:
    raw = base64.b64decode(b64)
    if len(raw) < 44:
        raise ValueError("ciphertext too short")
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    per_key = _hkdf_key(boot_key, salt, b"hypertime-ids/log-key/v2")
    aad = AAD_LOG + json.dumps({"ts": ts, "m": meta}, separators=(",", ":"), ensure_ascii=False).encode()
    pt = AESGCM(per_key).decrypt(nonce, ct, aad)
    return json.loads(pt.decode())

SCHEMA_VERSION = 3
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA foreign_keys=ON;
PRAGMA trusted_schema=OFF;
PRAGMA secure_delete=ON;
PRAGMA mmap_size=268435456;
PRAGMA page_size=4096;
PRAGMA auto_vacuum=INCREMENTAL;
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  suspicious INTEGER NOT NULL,
  malicious INTEGER NOT NULL,
  color TEXT NOT NULL,
  cipher_b64 TEXT NOT NULL,
  sig_alg TEXT NOT NULL,
  sig_b64 TEXT NOT NULL,
  sig_pub_b64 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  name TEXT PRIMARY KEY,
  ct TEXT NOT NULL,
  salt BLOB NOT NULL,
  nonce BLOB NOT NULL,
  kdf TEXT NOT NULL,
  created_ts INTEGER NOT NULL,
  updated_ts INTEGER NOT NULL
);
"""

def db_connect(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _secure_touch_0600(path)
    con = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    con.execute("PRAGMA disable_load_extension=ON;")
    con.executescript(SCHEMA_SQL)
    ver = _db_get_meta(con, "schema_version")
    if ver is None:
        _db_set_meta(con, "schema_version", str(SCHEMA_VERSION))
    elif int(ver) < SCHEMA_VERSION:
        _db_set_meta(con, "schema_version", str(SCHEMA_VERSION))
    return con

def _db_get_meta(con: sqlite3.Connection, k: str) -> Optional[str]:
    cur = con.execute("SELECT v FROM meta WHERE k = ?", (k,))
    row = cur.fetchone()
    return row[0] if row else None

def _db_set_meta(con: sqlite3.Connection, k: str, v: str) -> None:
    con.execute("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

def _ks_get_or_create_salt(con: sqlite3.Connection) -> bytes:
    v = _db_get_meta(con, "ks_salt_b64")
    if v:
        return base64.b64decode(v)
    salt = secrets.token_bytes(16)
    _db_set_meta(con, "ks_salt_b64", base64.b64encode(salt).decode())
    return salt

def _derive_kek(passphrase: str, ks_salt: bytes) -> bytes:
    global ARGON2_OK
    pp = passphrase.encode("utf-8", "ignore")
    out = _argon2_derive_or_none(pp, ks_salt, length=32, t=4, m=2**16, p=2)
    if out is not None:
        ARGON2_OK = True
        return out
    ARGON2_OK = False
    return _scrypt_safe(pp, ks_salt, dklen=32)

def keystore_unlock(con: sqlite3.Connection, passphrase: str) -> bytes:
    ks_salt = _ks_get_or_create_salt(con)
    return _derive_kek(passphrase, ks_salt)

def secrets_has(con: sqlite3.Connection, name: str) -> bool:
    cur = con.execute("SELECT 1 FROM secrets WHERE name = ? LIMIT 1", (name,))
    return cur.fetchone() is not None

def _derive_secret_key(kek: bytes, secret_salt: bytes) -> bytes:
    return _hkdf_key(kek, secret_salt, b"hypertime-ids/keystore/v2")

def secrets_put(con: sqlite3.Connection, kek: bytes, name: str, plaintext: bytes, kdf_label: str = "argon2id") -> None:
    secret_salt = secrets.token_bytes(16)
    data_key = _derive_secret_key(kek, secret_salt)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext, AAD_SECRET)
    ts = int(time.time())
    con.execute(
        """INSERT INTO secrets(name, ct, salt, nonce, kdf, created_ts, updated_ts)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET
             ct=excluded.ct, salt=excluded.salt, nonce=excluded.nonce,
             kdf=excluded.kdf, updated_ts=excluded.updated_ts""",
        (name, base64.b64encode(ct).decode(), secret_salt, nonce, kdf_label, ts, ts),
    )

def secrets_get(con: sqlite3.Connection, kek: Optional[bytes], name: str) -> Optional[bytes]:
    if kek is None:
        return None
    cur = con.execute("SELECT ct, salt, nonce FROM secrets WHERE name = ?", (name,))
    row = cur.fetchone()
    if not row:
        return None
    ct_b64, salt, nonce = row
    data_key = _derive_secret_key(kek, salt)
    pt = AESGCM(data_key).decrypt(nonce, base64.b64decode(ct_b64), AAD_SECRET)
    return pt

def secrets_delete(con: sqlite3.Connection, name: str) -> int:
    cur = con.execute("DELETE FROM secrets WHERE name = ?", (name,))
    return cur.rowcount

class PQSigner:
    def __init__(self, alg: str, kek: Optional[bytes], db: sqlite3.Connection):
        self.alg = alg
        self.sig = oqs.Signature(alg)
        self.priv: Optional[bytes] = None
        self.pub: bytes
        loaded = False
        if kek is not None and secrets_has(db, "oqs_sig_priv"):
            try:
                sk = secrets_get(db, kek, "oqs_sig_priv")
                pk = secrets_get(db, kek, "oqs_sig_pub")
                if sk and pk:
                    self.sig.import_secret_key(sk)
                    self.sig.import_public_key(pk)
                    self.priv = sk
                    self.pub = pk
                    loaded = True
            except Exception:
                loaded = False
        if not loaded:
            pk = self.sig.generate_keypair()
            sk = self.sig.export_secret_key()
            self.priv = sk
            self.pub = pk

    def persist(self, kek: Optional[bytes], db: sqlite3.Connection):
        if kek is None or self.priv is None:
            return False
        try:
            secrets_put(db, kek, "oqs_sig_priv", self.priv, current_kdf_label())
            secrets_put(db, kek, "oqs_sig_pub", self.pub, current_kdf_label())
            return True
        except Exception:
            return False

    def sign(self, data: bytes) -> bytes:
        return self.sig.sign(data)

    def verify(self, data: bytes, sig: bytes, pub: bytes) -> bool:
        try:
            v = oqs.Signature(self.alg)
            return v.verify(data, sig, pub)
        except Exception:
            return False

def _beep_worker(seconds: int, interval: float = 0.25):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if IS_WINDOWS and winsound:
                winsound.Beep(1000, int(interval * 1000))
            else:
                sys.stdout.write("\a"); sys.stdout.flush()
        except Exception:
            pass
        time.sleep(interval)

def beep_background(seconds: int):
    if seconds <= 0:
        return
    t = threading.Thread(target=_beep_worker, args=(seconds,), daemon=True)
    t.start()

def alert(msg: str, do_beep: bool = True):
    safe = bleach.clean(msg or "", strip=True)
    print(f"[HYPERTIME IDS ALERT] {safe}")
    if do_beep and ALERT_ON_ANY_ACTION:
        beep_background(BEEP_SECONDS)

def prime_cpu_readings():
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except Exception:
            pass

def sweep_system() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    prime_cpu_readings()
    processes: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cmdline']):
        try:
            info = proc.info
            info["cpu_percent"] = psutil.Process(info["pid"]).cpu_percent(interval=0.15)
            if info.get("cpu_percent", 0.0) >= 80.0:
                info["cpu_anomaly"] = True
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    sockets: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                sockets.append({
                    "pid": conn.pid,
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status
                })
            except Exception:
                continue
    except Exception:
        pass
    return processes, sockets

def _limit_str(s: Optional[str], n: int = 240) -> Optional[str]:
    if s is None:
        return None
    s2 = bleach.clean(s, strip=True)
    if len(s2) > n:
        return s2[:n]
    return s2

LLM_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "scope": {"type": "string", "enum": ["process", "socket"]},
                    "pid": {"type": ["integer", "null"]},
                    "name": {"type": ["string", "null"], "maxLength": 120},
                    "laddr": {"type": ["string", "null"], "maxLength": 64},
                    "raddr": {"type": ["string", "null"], "maxLength": 64},
                    "qid25_color": {"type": "string", "enum": ["BLUE","GREEN","YELLOW","RED"]},
                    "classification": {"type": "string", "enum": ["SAFE","SUSPICIOUS","MALICIOUS"]},
                    "reasoning": {"type": ["string", "null"], "maxLength": 160}
                },
                "required": ["scope","qid25_color","classification"]
            },
            "maxItems": 200
        },
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "safe": {"type": "integer", "minimum": 0},
                "suspicious": {"type": "integer", "minimum": 0},
                "malicious": {"type": "integer", "minimum": 0}
            },
            "required": ["safe","suspicious","malicious"]
        }
    },
    "required": ["analysis","summary"],
    "additionalProperties": False
}

CONTRACT_PROMPT = """
You are Hypertime IDS. Return ONE JSON object only. No prose, no explanations, no code fences, no extra text.
TASK
- Classify processes and sockets from INPUT.
- For each item, set qid25_color, classification, and a short neutral reasoning (<= 20 words). Use null when unknown.
STRICT OUTPUT
- Exactly: {"analysis":[...],"summary":{"safe":int,"suspicious":int,"malicious":int}}
- analysis items use ONLY keys:
  scope ("process"|"socket"), pid (int|null), name (string|null<=120),
  laddr (string|null<=64), raddr (string|null<=64),
  qid25_color ("BLUE"|"GREEN"|"YELLOW"|"RED"),
  classification ("SAFE"|"SUSPICIOUS"|"MALICIOUS"),
  reasoning (ASCII string|null<=160)
- Counts in summary MUST match analysis.
RULES
- Do not invent values. Unknown -> null.
- Neutral wording; never echo secrets.
- Prefer SUSPICIOUS over MALICIOUS if evidence is incomplete; SAFE only for benign signals.
- Order: MALICIOUS first, then SUSPICIOUS, then SAFE; ties by higher CPU, then PID.
- When uncertain: SUSPICIOUS.
FINAL SHAPE (repeat exactly keys):
{"analysis":[{"scope":"process|socket","pid":int|null,"name":str|null,"laddr":str|null,"raddr":str|null,"qid25_color":"BLUE|GREEN|YELLOW|RED","classification":"SAFE|SUSPICIOUS|MALICIOUS","reasoning":str|null}],"summary":{"safe":0,"suspicious":0,"malicious":0}}
""".strip()

def sanitize_strings(obj: Any) -> Any:
    if isinstance(obj, str):
        return _limit_str(obj, 240)
    if isinstance(obj, list):
        return [sanitize_strings(x) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize_strings(v) for k, v in obj.items()}
    return obj

def _pack_process_for_llm(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pid": p.get("pid") if isinstance(p.get("pid"), int) else None,
        "name": _limit_str(p.get("name"), 80),
        "username": _limit_str(p.get("username"), 60),
        "cpu_percent": float(p.get("cpu_percent", 0.0)) if isinstance(p.get("cpu_percent", 0.0), (int, float)) else 0.0,
        "cpu_anomaly": bool(p.get("cpu_anomaly", False)),
    }

def _pack_socket_for_llm(s: Dict[str, Any]) -> Dict[str, Any]:
    l = _limit_str(s.get("laddr"), 64)
    r = _limit_str(s.get("raddr"), 64)
    pid = s.get("pid")
    pid = pid if isinstance(pid, int) else None
    return {"pid": pid, "laddr": l, "raddr": r}

def _minimize_payload(processes: List[Dict[str, Any]], sockets: List[Dict[str, Any]]) -> Dict[str, Any]:
    P_MAX = 60
    S_MAX = 100
    procs_small = [_pack_process_for_llm(p) for p in processes[:P_MAX]]
    socks_small = [_pack_socket_for_llm(s) for s in sockets[:S_MAX]]
    return {"processes": procs_small, "sockets": socks_small}

_EMPTY_JSON = {"analysis": [], "summary": {"safe": 0, "suspicious": 0, "malicious": 0}}

def _strip_code_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s, count=1)
        s = re.sub(r"\s*```$", "", s, count=1)
    return s.strip()

def _extract_json_object(s: str) -> Optional[str]:
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return s[start:end+1]

def _clean_control_chars(s: str) -> str:
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", s)

def _coerce_model_json(raw: str) -> Dict[str, Any]:
    if not isinstance(raw, str):
        return _EMPTY_JSON
    s = _strip_code_fences(_clean_control_chars(raw))
    try:
        return json.loads(s)
    except Exception:
        pass
    j = _extract_json_object(s)
    if j:
        try:
            return json.loads(j)
        except Exception:
            j2 = re.sub(r",\s*([}\]])", r"\1", j)
            try:
                return json.loads(j2)
            except Exception:
                pass
    return _EMPTY_JSON

def _get_api_key_from_keystore(state: "State") -> Optional[str]:
    if state.kek is not None and secrets_has(state.db, "openai_api_key"):
        try:
            return (secrets_get(state.db, state.kek, "openai_api_key") or b"").decode("utf-8", "ignore")
        except Exception as e:
            print("[Keystore] decrypt failed:", e)
            return None
    return os.getenv("OPENAI_API_KEY") or None

async def _post_chat(json_body: dict, api_key: str) -> dict:
    if not api_key:
        raise RuntimeError("No OpenAI API key available.")
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    if azure_endpoint:
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", OPENAI_MODEL)
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
        base = azure_endpoint.rstrip("/")
        path = f"/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        headers = {"api-key": api_key, "Content-Type": "application/json"}
        base_url = base
    else:
        base_url = API_BASE
        path = "/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    max_attempts = 4
    backoff = 1.2
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=120.0, base_url=base_url, http2=True) as client:
                r = await client.post(path, headers=headers, json=json_body)
                if r.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
                r.raise_for_status()
                return r.json()
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError):
            if attempt == max_attempts:
                raise
            sleep_s = random.uniform(0, backoff * (2 ** attempt))
            if not (globals().get("STATE") and getattr(STATE, "quiet_ui", False)):
                print(f"[LLM] transient error (attempt {attempt}/{max_attempts}), retrying in {sleep_s:.1f}s...")
            await asyncio.sleep(sleep_s)

async def query_llm(state: "State", processes: List[Dict[str, Any]], sockets: List[Dict[str, Any]], offline: bool = False) -> Dict[str, Any]:
    if offline:
        analysis, summary = [], {"safe":0, "suspicious":0, "malicious":0}
        for p in processes[:60]:
            cls = "SUSPICIOUS" if p.get("cpu_anomaly") else "SAFE"
            if cls == "SUSPICIOUS":
                summary["suspicious"] += 1
            else:
                summary["safe"] += 1
            analysis.append({
                "scope": "process",
                "pid": p.get("pid") if isinstance(p.get("pid"), int) else None,
                "name": _limit_str(p.get("name")),
                "laddr": None, "raddr": None,
                "qid25_color": "YELLOW" if cls == "SUSPICIOUS" else "GREEN",
                "classification": cls,
                "reasoning": "Sustained CPU anomaly." if cls == "SUSPICIOUS" else "Benign idle behavior."
            })
        c = 0
        for s in sockets[:100]:
            if not isinstance(s.get("pid"), int):
                analysis.append({
                    "scope": "socket", "pid": None, "name": None,
                    "laddr": _limit_str(s.get("laddr"), 64),
                    "raddr": _limit_str(s.get("raddr"), 64),
                    "qid25_color": "YELLOW",
                    "classification": "SUSPICIOUS",
                    "reasoning": "Socket lacks PID mapping."
                })
                summary["suspicious"] += 1; c += 1
                if c >= 10:
                    break
        return {"analysis": sanitize_strings(analysis), "summary": summary}
    api_key = _get_api_key_from_keystore(state)
    if not api_key:
        raise RuntimeError("No API key available (unlock keystore or set env).")
    payload = _minimize_payload(processes, sockets)
    input_blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    body = {
        "model": OPENAI_MODEL,
        "temperature": 0,
        "max_tokens": 700,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are a cybersecurity IDS that outputs valid JSON only."},
            {"role": "user", "content": CONTRACT_PROMPT},
            {"role": "user", "content": "INPUT:\n"+input_blob}
        ]
    }
    data = await _post_chat(body, api_key)
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    obj = _coerce_model_json(content)
    try:
        Draft7Validator(LLM_SCHEMA).validate(obj)
    except Exception:
        if isinstance(obj, dict):
            obj.setdefault("analysis", [])
            obj.setdefault("summary", {"safe":0,"suspicious":0,"malicious":0})
            try:
                Draft7Validator(LLM_SCHEMA).validate(obj)
            except Exception:
                obj = _EMPTY_JSON
        else:
            obj = _EMPTY_JSON
    return sanitize_strings(obj)

def _index_by_pid(processes: List[Dict[str, Any]]):
    idx = {}
    for p in processes:
        pid = p.get("pid")
        if isinstance(pid, int):
            idx[pid] = p
    return idx

def _sockets_by_pid(sockets: List[Dict[str, Any]]):
    m: Dict[int, List[Dict[str, Any]]] = {}
    for s in sockets:
        pid = s.get("pid")
        if isinstance(pid, int):
            m.setdefault(pid, []).append(s)
    return m

def _collect_pids(analysis: List[Dict[str, Any]]):
    pids = set()
    reasons: Dict[int, List[str]] = {}
    for item in analysis:
        cls = item.get("classification")
        if cls in ("SUSPICIOUS", "MALICIOUS"):
            pid = item.get("pid")
            if isinstance(pid, int) and pid > 1:
                pids.add(pid)
                if item.get("reasoning"):
                    reasons.setdefault(pid, []).append(item["reasoning"])
    return pids, reasons

def safe_text(x: str) -> str:
    return _limit_str(x, 400) or ""

def print_manual_kill_sheet(analysis: List[Dict[str, Any]], processes: List[Dict[str, Any]], sockets: List[Dict[str, Any]]):
    pid_idx = _index_by_pid(processes)
    sock_idx = _sockets_by_pid(sockets)
    pids, reasons = _collect_pids(analysis)
    unknown_sock_hits = [a for a in analysis if a.get("scope") == "socket" and a.get("classification") in ("SUSPICIOUS", "MALICIOUS") and not isinstance(a.get("pid"), int)]
    if not pids and not unknown_sock_hits:
        print("[Manual] Nothing to kill; no suspicious processes found.")
        return
    print("\n========== Hypertime Manual Kill Sheet ==========")
    if pids:
        ordered = sorted(pids, key=lambda pid: -float(pid_idx.get(pid, {}).get("cpu_percent", 0.0)))
        for pid in ordered:
            info = pid_idx.get(pid, {})
            name = safe_text(info.get("name") or "unknown")
            user = safe_text(info.get("username") or "?")
            cpu = float(info.get("cpu_percent", 0.0))
            cmd = safe_text(" ".join(info.get("cmdline") or [])[:400])
            tag = "MAL" if any(a.get("pid")==pid and a.get("classification")=="MALICIOUS" for a in analysis) else "SUS"
            print(f"[{tag}] PID {pid:<6} user={user:<12} cpu={cpu:>5.1f}%  name={name}")
            if cmd:
                print(f"      cmd: {cmd}")
            if reasons.get(pid):
                for r in reasons[pid][:3]:
                    print(f"      why: {safe_text(r)}")
            remotes = sorted({s.get('raddr') for s in sock_idx.get(pid, []) if s.get('raddr')})
            if remotes:
                remotes_txt = safe_text(", ".join(remotes[:6]))
                print(f"      net: {remotes_txt}" + (" ..." if len(remotes) > 6 else ""))
            if IS_WINDOWS:
                print(f"   to kill: taskkill /PID {pid} /T /F")
            else:
                print(f"   to kill: kill -TERM {pid} || (sleep 3; kill -KILL {pid})")
            print("-")
    if unknown_sock_hits:
        print("\n[Note] Suspicious sockets without PID mapping:")
        for s in unknown_sock_hits[:8]:
            l = safe_text(s.get("laddr") or "?")
            r = safe_text(s.get("raddr") or "?")
            why = safe_text(s.get("reasoning") or "")
            print(f"  socket laddr={l} raddr={r}  {why}")
    print("=================================================\n")

def cpu_mult(cpu: float) -> float:
    if cpu >= 80: return 0.45
    if cpu >= 60: return 0.70
    if cpu >= 40: return 0.85
    return 1.00

def truncated_exp_minutes(a: float, b: float, lam: float = 1/90.0) -> float:
    u = random.random()
    ea, eb = math.exp(-lam*a), math.exp(-lam*b)
    t = -math.log(ea - u*(ea - eb)) / lam
    return max(a, min(b, t))

def rotate_color(prev: Optional[str]) -> str:
    if prev in QID25_COLORS:
        i = QID25_COLORS.index(prev)
        return QID25_COLORS[(i + random.choice([1, 1, 2])) % len(QID25_COLORS)]
    return random.choices(QID25_COLORS, weights=[2, 3, 4, 6], k=1)[0]

def next_delay_seconds(prev_color: Optional[str], override: Optional[str], base_min: float, base_max: float) -> Tuple[float, Dict[str, Any]]:
    base_min_rand = truncated_exp_minutes(base_min, base_max)
    cpu = psutil.cpu_percent(interval=0.6)
    color = override or rotate_color(prev_color)
    m = COLOR_MULT[color] * cpu_mult(cpu)
    delay_min = max(10, min(360, base_min_rand * m))
    return delay_min * 60.0, {"color": color, "cpu": cpu, "base_min": base_min_rand, "delay_min": delay_min}

def summarize_color(summary: Dict[str, int]) -> str:
    mal = summary.get("malicious", 0)
    sus = summary.get("suspicious", 0)
    if mal > 0: return "RED"
    if sus > 0: return "YELLOW"
    return "GREEN"

def db_insert_log(con: sqlite3.Connection, ts: int, sus: int, mal: int, color: str, env: Dict[str, str]) -> None:
    con.execute(
        "INSERT INTO logs(ts, suspicious, malicious, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, int(sus), int(mal), safe_text(color), env["cipher_b64"], env["sig_alg"], env["sig_b64"], env["sig_pub_b64"])
    )

def db_list_logs(con: sqlite3.Connection, limit: int = 10) -> List[Tuple[int,int,int,int,str]]:
    cur = con.execute("SELECT id, ts, suspicious, malicious, color FROM logs ORDER BY id DESC LIMIT ?", (int(limit),))
    return cur.fetchall()

def db_get_log_row(con: sqlite3.Connection, log_id: int):
    cur = con.execute("SELECT id, ts, suspicious, malicious, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64 FROM logs WHERE id = ?", (int(log_id),))
    row = cur.fetchone()
    return row if row else None

def db_purge_older_than(con: sqlite3.Connection, cutoff_ts: int) -> int:
    cur = con.execute("DELETE FROM logs WHERE ts < ?", (int(cutoff_ts),))
    return cur.rowcount

def db_vacuum(con: sqlite3.Connection) -> None:
    con.execute("PRAGMA incremental_vacuum")

class State:
    def __init__(self, db: sqlite3.Connection, key: bytes):
        self.db = db
        self.key = key
        self.kek: Optional[bytes] = None
        self.signer = PQSigner(SIG_ALG, None, db)
        self.running: bool = False
        self.last_color: Optional[str] = None
        self.base_min: float = float(BASE_MIN)
        self.base_max: float = float(BASE_MAX)
        self.last_summary: Dict[str,int] = {"safe":0,"suspicious":0,"malicious":0}
        self.last_scan_ts: Optional[int] = None
        self.next_meta: Dict[str,Any] = {}
        self.force_event = asyncio.Event()
        self.offline: bool = False
        self.err_streak: int = 0
        self.cb_open_until: float = 0.0
        self.quiet_ui: bool = False

STATE: Optional[State] = None

async def run_scan_once(state: State) -> Dict[str, Any]:
    procs, socks = sweep_system()
    now = time.time()
    offline = state.offline or (state.cb_open_until > now)
    try:
        llm = await query_llm(state, procs, socks, offline=offline)
        state.err_streak = 0
    except (ValidationError, httpx.HTTPError, httpx.TimeoutException, httpx.NetworkError, RuntimeError) as e:
        if not state.quiet_ui:
            print("[HYPERTIME IDS] LLM error:", e)
        state.err_streak += 1
        if state.err_streak >= 3:
            state.cb_open_until = time.time() + 300
            if not state.quiet_ui:
                print("[LLM] Circuit breaker OPEN for 5 minutes; switching to offline heuristic mode.")
        llm = await query_llm(state, procs, socks, offline=True)
    except Exception as e:
        if not state.quiet_ui:
            print("[HYPERTIME IDS] Unexpected LLM error:", e)
        llm = await query_llm(state, procs, socks, offline=True)
    summary = llm.get("summary", {"safe":0,"suspicious":0,"malicious":0})
    state.last_summary = {k:int(summary.get(k,0)) for k in ("safe","suspicious","malicious")}
    state.last_scan_ts = int(time.time())
    current_color = summarize_color(state.last_summary)
    if state.last_summary.get("suspicious",0) > 0 or state.last_summary.get("malicious",0) > 0:
        oqs_flag = os.getenv("HYPERTIME_OQS_ENABLED", "0")
        if not state.quiet_ui:
            alert(f"Detections: S={state.last_summary.get('suspicious',0)} M={state.last_summary.get('malicious',0)} (OQS={oqs_flag})")
            print_manual_kill_sheet(llm.get("analysis", []), procs, socks)
    else:
        if not state.quiet_ui:
            print("[Hypertime] All clear.")
    env = encrypt_log_envelope(llm, state.key, state.last_scan_ts, {"color": current_color}, state.signer)
    try:
        db_insert_log(state.db, state.last_scan_ts, state.last_summary["suspicious"], state.last_summary["malicious"], current_color, env)
    except Exception as e:
        if not state.quiet_ui:
            print("[DB] insert failed:", e)
    del procs, socks, llm
    gc.collect()
    secs, meta = next_delay_seconds(prev_color=state.last_color, override=current_color, base_min=state.base_min, base_max=state.base_max)
    state.last_color = meta["color"]
    state.next_meta = meta
    if not state.quiet_ui:
        print(f"[Scheduler] next={meta['delay_min']:.1f}m color={meta['color']} cpu={meta['cpu']:.1f}% base~{meta['base_min']:.1f}m")
    return {"ok": True}

async def scanning_loop(state: State):
    while True:
        if not state.running:
            await asyncio.sleep(0.25)
            continue
        try:
            await run_scan_once(state)
        except Exception as e:
            if not state.quiet_ui:
                print("[Scan] unexpected error:", e)
        total = max(5.0, float(state.next_meta.get("delay_min", 15.0) * 60.0))
        start = time.time()
        while time.time() - start < total:
            if not state.running:
                break
            if state.force_event.is_set():
                state.force_event.clear()
                break
            await asyncio.sleep(0.25)

async def ainput(prompt: str) -> str:
    try:
        s = await asyncio.to_thread(input, prompt)
    except EOFError:
        return ""
    return s

async def agetpass(prompt: str) -> str:
    try:
        return await asyncio.to_thread(getpass.getpass, prompt)
    except EOFError:
        return ""

def ts_to_str(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

def print_status(state: State):
    print("\n--- Status ---")
    print(f" Running: {state.running}")
    print(f" Last scan: {ts_to_str(state.last_scan_ts) if state.last_scan_ts else 'never'}")
    print(f" Last summary: safe={state.last_summary.get('safe',0)}  sus={state.last_summary.get('suspicious',0)}  mal={state.last_summary.get('malicious',0)}")
    nm = state.next_meta or {}
    if nm:
        print(f" Next: ~{nm.get('delay_min',0):.1f}m  color={nm.get('color','?')}  cpu={nm.get('cpu',0):.1f}%  base~{nm.get('base_min',0):.1f}m")
    print(f" Schedule: {state.base_min:.0f}–{state.base_max:.0f} min")
    print(f" OQS enabled: {os.getenv('HYPERTIME_OQS_ENABLED','0') == '1'}")
    print(f" Offline mode: {state.offline or (state.cb_open_until > time.time())}")
    if state.cb_open_until > time.time():
        rem = int(state.cb_open_until - time.time())
        print(f" Circuit breaker open for ~{rem}s")
    ks = "unlocked" if state.kek is not None else "locked"
    has_secret = secrets_has(state.db, "openai_api_key")
    print(f" Keystore: {ks} | API key stored: {has_secret}")
    print("--------------\n")

def print_menu():
    menu = """
Hypertime IDS TUI
 1) Start scanning
 2) Stop scanning
 3) Force scan now
 4) View status
 5) List recent logs
 6) View + decrypt a log by ID
 7) Purge logs older than N days
 8) Toggle beeps
 9) Change schedule baseline (min max minutes)
10) OQS info
11) Help
12) Export decrypted log to file
13) Search decrypted logs (last N) by keyword
14) Vacuum database
15) Toggle offline mode (LLM disabled)
16) Unlock keystore (enter passphrase)
17) Set/Update OpenAI API key in keystore
18) Remove OpenAI API key from keystore
19) Persist OQS signature key to keystore
20) Show current OQS signature public key (base64, short)
 0) Quit
"""
    print(menu.strip())

def print_help():
    txt = """
Alert-only. Logs use per-record HKDF keys with AES-GCM and AEAD, signed with OQS signatures. Boot key mixes PQ KEM and memory-hard KDF. Keystore encrypts secrets using AES-GCM with per-secret HKDF keys and AEAD. DB file perms hardened to 0600. If no API key is available, offline heuristics are used.
"""
    print(textwrap.dedent(txt).strip())

def print_oqs_info(state: State):
    print("\n--- OQS Info ---")
    print(f" KEM: {KEM_ALG}")
    print(f" SIG: {SIG_ALG}")
    print(f" OQS available: {HAVE_OQS}")
    print(f" Enabled this run: {os.getenv('HYPERTIME_OQS_ENABLED','0')=='1'}")
    short = base64.b64encode(state.signer.pub)[:44].decode(errors="ignore")
    print(f" SIG pub (b64, first 44): {short}...")
    try:
        mechs_kem = oqs.get_enabled_kem_mechanisms()
        mechs_sig = oqs.get_enabled_sig_mechanisms()
        print(" Enabled KEMs (first 10):", ", ".join(mechs_kem[:10]))
        print(" Enabled SIGs (first 10):", ", ".join(mechs_sig[:10]))
    except Exception as e:
        print(" Can't list mechanisms:", e)
    print("---------------\n")

def _export_log_to_file(state: State, log_id: int, path: str) -> bool:
    try:
        row = db_get_log_row(state.db, log_id)
        if not row:
            print("Not found."); return False
        _id, ts, sus, mal, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64 = row
        obj = decrypt_log_envelope(cipher_b64, state.key, ts, {"color": color})
        tmp = f"{path}.tmp-{secrets.token_hex(6)}"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2))
        os.replace(tmp, path)
        print(f"Exported #{_id} to {path}")
        return True
    except Exception as e:
        print("Export failed:", e)
        try:
            if 'tmp' in locals() and os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False

def _search_logs(state: State, n: int, keyword: str):
    rows = db_list_logs(state.db, n)
    keyword = keyword.lower()
    hits = 0
    for _id, ts, sus, mal, color in rows:
        row = db_get_log_row(state.db, _id)
        if not row:
            continue
        _, ts, sus, mal, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64 = row
        try:
            obj = decrypt_log_envelope(cipher_b64, state.key, ts, {"color": color})
            j = json.dumps(obj, ensure_ascii=False)
            if keyword in j.lower():
                ts_s = ts_to_str(ts)
                print(f"- Hit #{_id} [{ts_s}] S={sus} M={mal} {color}")
                hits += 1
        except Exception:
            continue
    if hits == 0:
        print("(no hits)")

def _verify_log_signature(state: State, row) -> bool:
    _, ts, _, _, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64 = row
    try:
        pub = base64.b64decode(sig_pub_b64)
        raw = base64.b64decode(cipher_b64)
        aad = AAD_LOG + json.dumps({"ts": ts, "m": {"color": color}}, separators=(",", ":"), ensure_ascii=False).encode() + AAD_LOG_META
        v = oqs.Signature(sig_alg)
        return v.verify(raw + aad, base64.b64decode(sig_b64), pub)
    except Exception:
        return False

async def tui_loop(state: State):
    global ALERT_ON_ANY_ACTION
    while True:
        print_menu()
        choice = safe_text((await ainput("Select> ")).strip())
        if choice == "1":
            if state.running:
                print("Already running.")
            else:
                state.running = True
                print("Scanning started.")
        elif choice == "2":
            if not state.running:
                print("Already stopped.")
            else:
                state.running = False
                print("Scanning stopped.")
        elif choice == "3":
            if not state.running:
                print("Not running; starting a one-shot now...")
                state.running = True
                state.force_event.set()
            else:
                print("Forcing an immediate scan...")
                state.force_event.set()
        elif choice == "4":
            print_status(state)
        elif choice == "5":
            try:
                state.quiet_ui = True
                n_str = safe_text((await ainput("How many (1-200, default 10)? ")).strip())
                n = 10
                if n_str.isdigit():
                    n = max(1, min(200, int(n_str)))
                rows = db_list_logs(state.db, n)
                if not rows:
                    print("(no logs)")
                else:
                    print("\nID   Timestamp            S   M   Color   SIG")
                    print("-----------------------------------------------")
                    for _id, ts, sus, mal, color in rows:
                        row = db_get_log_row(state.db, _id)
                        ok = _verify_log_signature(state, row) if row else False
                        print(f"{_id:<4} {ts_to_str(ts):<20} {sus:<3} {mal:<3} {safe_text(color):<6} {'OK' if ok else 'BAD'}")
                    print("")
            finally:
                state.quiet_ui = False
        elif choice == "6":
            try:
                state.quiet_ui = True
                id_str = safe_text((await ainput("Log ID to decrypt: ")).strip())
                if not id_str.isdigit():
                    print("Invalid ID."); continue
                row = db_get_log_row(state.db, int(id_str))
                if not row:
                    print("Not found."); continue
                _id, ts, sus, mal, color, cipher_b64, sig_alg, sig_b64, sig_pub_b64 = row
                try:
                    ok = _verify_log_signature(state, row)
                    obj = decrypt_log_envelope(cipher_b64, state.key, ts, {"color": color})
                except Exception as e:
                    print("Decrypt failed:", e); continue
                j = json.dumps(obj, ensure_ascii=False, indent=2)
                print(f"\n--- Decrypted Log #{_id} at {ts_to_str(ts)} (SIG {'OK' if ok else 'BAD'}) ---")
                print(safe_text(j))
                print("-----------------------------------------------\n")
            finally:
                state.quiet_ui = False
        elif choice == "7":
            d_str = safe_text((await ainput("Delete logs older than N days: ")).strip())
            if not d_str or not d_str.isdigit():
                print("Invalid number of days."); continue
            days = int(d_str)
            cutoff = int(time.time()) - days*86400
            try:
                deleted = db_purge_older_than(state.db, cutoff)
                print(f"Deleted {deleted} rows.")
            except Exception as e:
                print("Purge failed:", e)
        elif choice == "8":
            ALERT_ON_ANY_ACTION = not ALERT_ON_ANY_ACTION
            print(f"Beeps now {'ON' if ALERT_ON_ANY_ACTION else 'OFF'}.")
        elif choice == "9":
            a = safe_text((await ainput("New min minutes (>=10): ")).strip())
            b = safe_text((await ainput("New max minutes (>min, <=360): ")).strip())
            def _is_num(x:str) -> bool:
                try:
                    float(x); return True
                except:
                    return False
            if not (_is_num(a) and _is_num(b)):
                print("Invalid numbers."); continue
            mn = float(a); mx = float(b)
            if mn < 10 or mx <= mn or mx > 360:
                print("Out of range."); continue
            state.base_min, state.base_max = mn, mx
            print(f"Schedule updated to {mn:.0f}–{mx:.0f} minutes.")
        elif choice == "10":
            print_oqs_info(state)
        elif choice == "11":
            print_help()
        elif choice == "12":
            id_str = safe_text((await ainput("Log ID to export: ")).strip())
            path = safe_text((await ainput("Write to path (will overwrite): ")).strip())
            if not id_str.isdigit() or not path:
                print("Invalid input."); continue
            _export_log_to_file(state, int(id_str), path)
        elif choice == "13":
            n_str = safe_text((await ainput("Search last N logs (1-200, default 50): ")).strip())
            n = 50
            if n_str.isdigit():
                n = max(1, min(200, int(n_str)))
            kw = safe_text((await ainput("Keyword: ")).strip())
            if not kw:
                print("Empty keyword."); continue
            _search_logs(state, n, kw)
        elif choice == "14":
            try:
                db_vacuum(state.db); print("Vacuum complete.")
            except Exception as e:
                print("Vacuum failed:", e)
        elif choice == "15":
            state.offline = not state.offline
            if state.offline:
                print("Offline heuristic mode ENABLED.")
            else:
                state.cb_open_until = 0.0
                state.err_streak = 0
                print("Offline heuristic mode DISABLED.")
        elif choice == "16":
            if state.kek is not None:
                print("Keystore already unlocked."); continue
            pw = await agetpass("Keystore passphrase (won't echo): ")
            if not pw:
                print("Empty passphrase; canceled."); continue
            try:
                state.kek = keystore_unlock(state.db, pw)
                print("Keystore unlocked.")
            except Exception as e:
                state.kek = None
                print("Unlock failed:", e)
        elif choice == "17":
            if state.kek is None:
                print("Keystore locked. Use option 16 first."); continue
            api = await agetpass("Enter OpenAI API key (won't echo): ")
            if not api:
                print("Empty key; canceled."); continue
            api_b = safe_text(api.strip()).encode()
            try:
                secrets_put(state.db, state.kek, "openai_api_key", api_b, current_kdf_label())
                print("OpenAI API key stored (encrypted).")
            except Exception as e:
                print("Store failed:", e)
        elif choice == "18":
            try:
                n = secrets_delete(state.db, "openai_api_key")
                print("Removed." if n else "No key stored.")
            except Exception as e:
                print("Remove failed:", e)
        elif choice == "19":
            if state.kek is None:
                print("Keystore locked. Use option 16 first."); continue
            ok = state.signer.persist(state.kek, state.db)
            print("Persisted." if ok else "Persist failed.")
        elif choice == "20":
            short = base64.b64encode(state.signer.pub)[:88].decode(errors="ignore")
            print(f"OQS SIG pub (b64): {short}...")
        elif choice == "0":
            print("Bye."); return
        else:
            print("Unknown selection.")

async def main():
    key = derive_boot_key()
    db = db_connect(DEFAULT_DB)
    global STATE
    STATE = State(db=db, key=key)
    scanner = asyncio.create_task(scanning_loop(STATE))
    try:
        await tui_loop(STATE)
    finally:
        STATE.running = False
        await asyncio.sleep(0.1)
        scanner.cancel()
        try:
            await scanner
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[HYPERTIME IDS] Stopped by user.")

