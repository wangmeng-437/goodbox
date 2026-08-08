# -*- coding: utf-8 -*-
import base64
import json
import random
import re
import struct
import time
import os
import uuid
from urllib.parse import quote

try:
    import requests
except Exception:
    requests = None

try:
    from base.spider import Spider as BaseSpider
except Exception:
    class BaseSpider(object):
        pass



# =========================
# Pure Python AES/RSA helpers
# No Crypto / pycryptodome dependency.
# =========================

_S_BOX = [
99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
]
_INV_S_BOX = [
82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,
84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,
114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,
144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,
58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,
71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,
31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,
160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125
]
_RCON = [0,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty pkcs7 data")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad pkcs7 padding")
    return data[:-n]


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _sub_word(w):
    return bytes(_S_BOX[x] for x in w)


def _rot_word(w):
    return w[1:] + w[:1]


class _AES:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key length must be 16/24/32 bytes")
        self.key = key
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self._expand_key()

    def _expand_key(self):
        words = [self.key[i:i+4] for i in range(0, len(self.key), 4)]
        for i in range(self.nk, 4 * (self.nr + 1)):
            temp = words[i - 1]
            if i % self.nk == 0:
                temp = _sub_word(_rot_word(temp))
                temp = bytes([temp[0] ^ _RCON[i // self.nk]]) + temp[1:]
            elif self.nk > 6 and i % self.nk == 4:
                temp = _sub_word(temp)
            words.append(_xor(words[i - self.nk], temp))
        return [b"".join(words[i:i+4]) for i in range(0, len(words), 4)]

    @staticmethod
    def _to_state(block):
        return [[block[r + 4*c] for c in range(4)] for r in range(4)]

    @staticmethod
    def _from_state(s):
        return bytes(s[r][c] for c in range(4) for r in range(4))

    @staticmethod
    def _add_round_key(s, k):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= k[r + 4*c]

    @staticmethod
    def _sub_bytes(s):
        for r in range(4):
            for c in range(4):
                s[r][c] = _S_BOX[s[r][c]]

    @staticmethod
    def _inv_sub_bytes(s):
        for r in range(4):
            for c in range(4):
                s[r][c] = _INV_S_BOX[s[r][c]]

    @staticmethod
    def _shift_rows(s):
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]

    @staticmethod
    def _inv_shift_rows(s):
        for r in range(1, 4):
            s[r] = s[r][-r:] + s[r][:-r]

    @staticmethod
    def _mix_columns(s):
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)

    @staticmethod
    def _inv_mix_columns(s):
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)

    def encrypt_block(self, block):
        s = self._to_state(block)
        self._add_round_key(s, self.round_keys[0])
        for rnd in range(1, self.nr):
            self._sub_bytes(s)
            self._shift_rows(s)
            self._mix_columns(s)
            self._add_round_key(s, self.round_keys[rnd])
        self._sub_bytes(s)
        self._shift_rows(s)
        self._add_round_key(s, self.round_keys[self.nr])
        return self._from_state(s)

    def decrypt_block(self, block):
        s = self._to_state(block)
        self._add_round_key(s, self.round_keys[self.nr])
        for rnd in range(self.nr - 1, 0, -1):
            self._inv_shift_rows(s)
            self._inv_sub_bytes(s)
            self._add_round_key(s, self.round_keys[rnd])
            self._inv_mix_columns(s)
        self._inv_shift_rows(s)
        self._inv_sub_bytes(s)
        self._add_round_key(s, self.round_keys[0])
        return self._from_state(s)

    def encrypt_ecb(self, data):
        data = _pkcs7_pad(data)
        return b"".join(self.encrypt_block(data[i:i+16]) for i in range(0, len(data), 16))

    def decrypt_ecb(self, data):
        out = b"".join(self.decrypt_block(data[i:i+16]) for i in range(0, len(data), 16))
        return _pkcs7_unpad(out)

    def encrypt_cbc(self, data, iv):
        data = _pkcs7_pad(data)
        prev = iv
        out = []
        for i in range(0, len(data), 16):
            block = _xor(data[i:i+16], prev)
            enc = self.encrypt_block(block)
            out.append(enc)
            prev = enc
        return b"".join(out)


def _der_len(data, pos):
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7f
    return int.from_bytes(data[pos:pos+n], "big"), pos + n


def _der_tlv(data, pos):
    tag = data[pos]
    pos += 1
    length, pos = _der_len(data, pos)
    return tag, data[pos:pos+length], pos + length


def _rsa_pub_from_b64(public_key_b64):
    text = re.sub(r"-----BEGIN [^-]+-----|-----END [^-]+-----|\s+", "", str(public_key_b64 or ""))
    der = base64.b64decode(text)
    tag, seq, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("bad rsa public key")
    p = 0
    tag1, val1, p = _der_tlv(seq, p)
    if tag1 == 0x30 and p < len(seq):
        tag2, bit_string, p = _der_tlv(seq, p)
        if tag2 != 0x03:
            raise ValueError("bad rsa public key")
        tag3, rsa_seq, _ = _der_tlv(bit_string[1:], 0)
        if tag3 != 0x30:
            raise ValueError("bad rsa public key")
    else:
        rsa_seq = seq
    q = 0
    tag_n, n_bytes, q = _der_tlv(rsa_seq, q)
    tag_e, e_bytes, q = _der_tlv(rsa_seq, q)
    if tag_n != 0x02 or tag_e != 0x02:
        raise ValueError("bad rsa public key")
    return int.from_bytes(n_bytes.lstrip(b"\x00"), "big"), int.from_bytes(e_bytes.lstrip(b"\x00"), "big")


def _rsa_encrypt_pkcs1_v15(text, public_key_b64):
    msg = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    n, e = _rsa_pub_from_b64(public_key_b64)
    k = (n.bit_length() + 7) // 8
    if len(msg) > k - 11:
        raise ValueError("RSA message too long")
    ps_len = k - len(msg) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        ps.extend(x for x in os.urandom(ps_len - len(ps)) if x != 0)
    em = b"\x00\x02" + bytes(ps[:ps_len]) + b"\x00" + msg
    enc = pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")
    return base64.b64encode(enc).decode("utf-8")


class Spider(BaseSpider):
    CONFIG = {
        "appName": "橘汁",
        "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr8SzZhjYy+rsya1K09t8d2K50pWFoBkgUqMpKOiW+3IEVKd4eTdvg9RSOjQ82kypL6R9BnsmrS1V8s4PVDwjQbUtYhTPPC9Hz16qY7rpD6m0d2vr09/UpWQ5uOy9PR0QTrsioveZ+DIe9jc3C+zBCu/kZSY/R8stwJoiitki3gwIDAQAB",
        "dataKey": "DGVQRUX5R1LWWDLHTGJSUKG1DJRVPQ==",
        "dataIv": "OC1A06E197EF10CF3F6058CA7A803B5E",
        "pkg": "com.lxf.snzlcgtzxyx",
        "host": "",
        "site": "https://123-1349250429.cos.ap-shanghai.myqcloud.com/app.txt",
        "version": "3.0.2.1",
        "decrypt": "1"
    }

    def getName(self):
        return "橘汁"

    def init(self, extend=""):
        self.cfg = dict(self.CONFIG)
        if isinstance(extend, dict):
            self.cfg.update(extend)
        elif isinstance(extend, str) and extend.strip():
            try:
                obj = json.loads(extend)
                if isinstance(obj, dict):
                    self.cfg.update(obj)
            except Exception:
                pass

        self.host = str(self.cfg.get("host", "")).rstrip("/")
        self.public_key = str(self.cfg.get("publicKey", ""))
        self.dynamic_key = ""
        self.data_key = str(self.cfg.get("dataKey", ""))
        self.data_iv = str(self.cfg.get("dataIv", ""))
        self.common_key = "ed5fdsgucxumegqa"
        self.session = requests.Session() if requests else None
        self.last_error = ""

        # 关键修复：
        # 绿豆 TVBox 在加载接口时会先调用 init/homeContent。
        # 原版 init 里立即联网获取动态域名和动态公钥，失败或网络慢会导致首页分类超时空白。
        # 本版 init 完全不联网，homeContent 也不联网；真正取资源时再懒加载。
        self._remote_classes = None
        self._remote_filters = None
        self._remote_id_by_static = {}
        self._remote_id_set = set()
        self._remote_name_by_id = {}
        self._default_category_ids = None
        self._home_blocks_cache = None

        if self.session:
            self.session.headers.update({"User-Agent": "okhttp/3.12.1"})

    def isVideoFormat(self, url):
        return bool(re.search(r"(?i)\.(?:mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(?:\?.*)?$", str(url)))

    def manualVideoCheck(self):
        return False

    # ---------- protobuf wire ----------
    @staticmethod
    def _varint(value):
        value = int(value)
        out = bytearray()
        while value > 0x7f:
            out.append((value & 0x7f) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    @classmethod
    def _pb_int(cls, field, value):
        return cls._varint(field << 3) + cls._varint(value)

    @classmethod
    def _pb_bytes(cls, field, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return cls._varint((field << 3) | 2) + cls._varint(len(value)) + value

    @staticmethod
    def _read_varint(data, pos):
        value = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            value |= (b & 0x7f) << shift
            if not b & 0x80:
                return value, pos
            shift += 7
            if shift > 70:
                raise ValueError("bad protobuf varint")
        raise ValueError("truncated protobuf varint")

    @classmethod
    def _pb_parse(cls, data):
        fields = {}
        pos = 0
        while pos < len(data):
            key, pos = cls._read_varint(data, pos)
            field, wire = key >> 3, key & 7
            if wire == 0:
                value, pos = cls._read_varint(data, pos)
            elif wire == 1:
                value = data[pos:pos + 8]
                pos += 8
            elif wire == 2:
                size, pos = cls._read_varint(data, pos)
                value = data[pos:pos + size]
                pos += size
            elif wire == 5:
                value = data[pos:pos + 4]
                pos += 4
            else:
                raise ValueError("unsupported protobuf wire type: %s" % wire)
            fields.setdefault(field, []).append(value)
        return fields

    @staticmethod
    def _first(fields, number, default=b""):
        values = fields.get(number)
        return values[0] if values else default

    @staticmethod
    def _text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", "ignore")
        return str(value or "")

    # ---------- crypto ----------
    @staticmethod
    def _random(length):
        chars = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        return "".join(random.choice(chars) for _ in range(max(0, length - 1))) + "="

    @staticmethod
    def _check_crypto():
        return True

    @classmethod
    def _aes_encrypt_ecb(cls, text, key):
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        raw = _AES(key.encode("utf-8")).encrypt_ecb(data)
        return base64.b64encode(raw).decode("utf-8")

    @classmethod
    def _aes_decrypt_ecb(cls, text, key):
        raw = base64.b64decode(str(text))
        dec = _AES(key.encode("utf-8")).decrypt_ecb(raw)
        return dec.decode("utf-8", "ignore")

    @classmethod
    def _aes_encrypt_cbc_hex(cls, text, key):
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        key_b = key.encode("utf-8")
        return _AES(key_b).encrypt_cbc(data, key_b).hex()

    @classmethod
    def _rsa_encrypt(cls, text, public_key_b64):
        return _rsa_encrypt_pkcs1_v15(text, public_key_b64)

    # ---------- request protocol ----------
    def _device(self):
        uid = uuid.uuid4().hex.upper()
        version = str(self.cfg.get("version", ""))
        return {
            "country": "CN", "vName": version, "cpuId": "MT6893Z%2FCZA", "young": 0,
            "facturer": "Xiaomi", "pkg": self.cfg.get("pkg", ""), "uuid": uid,
            "resolution": "1080x2272", "mac": "02%3A00%3A00%3A00%3A00%3A00", "abid": "397",
            "model": "M2012K11AC", "plat": "android", "udid": uid, "dpi": "440", "net": "1",
            "lang": "zh", "brand": "Xiaomi", "density": "2.75", "appName": self.cfg.get("appName", "橘汁"),
            "cpu": "arm64-v8a", "chid": "10000", "carrier": "%E8%81%94%E9%80%9A",
            "_vOsCode": 30, "vOs": "11", "v": 1, "tenantId": "",
            "vApp": version.replace(".", ""), "device": 0, "androidID": uid.lower()[:16]
        }

    def _public_headers(self, protobuf=True):
        key = self.dynamic_key or self.public_key
        device = self._device()
        timestamp = int(time.time() * 1000)
        random_str = self._random(16)
        vapp = device.get("vApp") or "3019"
        device["sig"] = self._rsa_encrypt(str(timestamp) + random_str + vapp, key)
        device["random_str"] = random_str
        device["timestamp"] = timestamp
        sig23 = self._aes_encrypt_ecb(str(timestamp) + random_str, self.data_iv)
        device["sig2"] = sig23[:8]
        device["sig3"] = sig23[8:]
        params = self._aes_encrypt_cbc_hex(json.dumps(device, ensure_ascii=False, separators=(",", ":")), self.common_key)
        ctype = "application/x-protobuf" if protobuf else "application/json; charset=utf-8"
        accept = "application/x-protobuf" if protobuf else "application/json"
        return {
            "User-Agent": "okhttp/3.12.1", "Accept": accept, "Content-Type": ctype,
            "publicParams": json.dumps({"paramsData": params}, ensure_ascii=False, separators=(",", ":"))
        }

    def _secure_body(self, params):
        timestamp = int(time.time() * 1000)
        random8 = self._random(8)
        fake20 = self._random(20)
        query = "&".join("%s=%s" % (k, v) for k, v in params.items() if v is not None and str(v) != "")
        encrypted = random8 + self._aes_encrypt_ecb(query + str(timestamp), self.data_key)
        return b"".join([
            self._pb_bytes(1, encrypted[:20]), self._pb_bytes(2, encrypted[20:]),
            self._pb_bytes(3, fake20), self._pb_int(4, timestamp), self._pb_bytes(5, random8)
        ])

    def _ensure_host(self):
        if self.host:
            return
        if not self.session:
            raise RuntimeError("缺少 requests 模块")
        site = str(self.cfg.get("site", "") or "")
        if not site:
            raise RuntimeError("没有配置动态域名 site")
        try:
            r = self.session.get(site, timeout=6)
            r.raise_for_status()
            obj = r.json()
            domain = str(obj.get("domain", "")).strip().rstrip("/")
            if not domain:
                raise RuntimeError("动态配置未返回 domain")
            self.host = domain
        except Exception as exc:
            self.last_error = "动态域名获取失败: %s" % exc
            raise RuntimeError(self.last_error)

    def _ensure_dynamic_key(self):
        # 动态公钥只尝试一次；失败时使用配置 publicKey 继续请求。
        if self.dynamic_key:
            return
        if getattr(self, "_dynamic_key_tried", False):
            return
        self._dynamic_key_tried = True
        try:
            self._load_dynamic_key()
        except Exception as exc:
            self.dynamic_key = ""
            self.last_error = "动态公钥获取失败: %s" % exc

    def _prepare_api(self, need_dynamic=True):
        self._ensure_host()
        if need_dynamic:
            self._ensure_dynamic_key()

    def _post(self, path, body):
        if not self.session:
            raise RuntimeError("缺少 requests 模块")
        self._prepare_api(True)
        r = self.session.post(
            self.host + path,
            data=body,
            headers=self._public_headers(True),
            timeout=10
        )
        if r.status_code >= 400:
            raise RuntimeError("HTTP %s: %s" % (r.status_code, r.text[:180]))
        return r.content

    def _get_json(self, path):
        if not self.session:
            raise RuntimeError("缺少 requests 模块")
        # 分类接口如果动态公钥慢，先不强制获取动态 key，使用配置 publicKey 发公共参数。
        self._prepare_api(False)
        r = self.session.get(
            self.host + path,
            headers=self._public_headers(False),
            timeout=8
        )
        if r.status_code >= 400:
            raise RuntimeError("HTTP %s: %s" % (r.status_code, r.text[:180]))
        return r.json()

    def _api_result_fields(self, raw):
        try:
            return self._pb_parse(raw)
        except Exception:
            # 如果服务端返回 JSON/HTML，直接抛出可读内容
            preview = raw[:180]
            try:
                preview = preview.decode("utf-8", "ignore")
            except Exception:
                preview = repr(preview)
            raise RuntimeError("非 Protobuf 响应: " + re.sub(r"\s+", " ", str(preview))[:180])

    def _api_data(self, raw):
        fields = self._api_result_fields(raw)
        data = self._first(fields, 3, b"")
        if data:
            return data

        # ApiResult 常见字段：1=code，2=message，3=data
        msg = self._text(self._first(fields, 2, b""))
        code = self._first(fields, 1, "")
        if msg:
            raise RuntimeError("ApiResult code=%s msg=%s" % (code, msg))
        return b""

    def _load_dynamic_key(self):
        self._ensure_host()
        timestamp = int(time.time() * 1000)
        random_str = self._random(16)
        sign = self._rsa_encrypt(str(timestamp) + random_str, self.public_key)
        body = b"".join([
            self._pb_int(1, timestamp),
            self._pb_bytes(2, sign),
            self._pb_bytes(3, self._random(16)),
            self._pb_bytes(4, random_str),
            self._pb_bytes(5, self._random(16))
        ])
        r = self.session.post(
            self.host + "/api/v5/find/app/zone",
            data=body,
            headers=self._public_headers(True),
            timeout=8
        )
        if r.status_code >= 400:
            raise RuntimeError("HTTP %s: %s" % (r.status_code, r.text[:180]))
        data = self._api_data(r.content)
        f = self._pb_parse(data)
        self.dynamic_key = "".join(self._text(self._first(f, n)) for n in (2, 3, 4, 5))

    def _post_category(self, body):
        errors = []
        for path in ("/api/proto/v5/drama/category", "/api/proto/v5/drama/getList"):
            try:
                return self._post(path, body)
            except Exception as exc:
                errors.append("%s => %s" % (path, exc))
        raise RuntimeError("；".join(errors))

    # ---------- response parsers ----------
    def _parse_cover(self, raw):
        f = self._pb_parse(raw)
        # 实际 proto 中 path/thumbnail 在 1/2 间，不同版本可能互换。
        a = self._text(self._first(f, 1))
        b = self._text(self._first(f, 2))
        path = a if a.startswith("http") else b
        thumb = b if b.startswith("http") else a
        return {"path": path or a or b, "thumb": thumb or b or a}

    def _parse_drama(self, raw):
        f = self._pb_parse(raw)
        cover_raw = self._first(f, 2, b"")
        cover = self._parse_cover(cover_raw) if cover_raw else {}

        vod_id = self._first(f, 3, "")
        # 标准字段：area=1 cover=2 id=3 brief=4 name=5 remark=6
        name = self._text(self._first(f, 5))
        if not name:
            # 兜底从所有字符串字段里找一个像标题的
            candidates = []
            for arr in f.values():
                for val in arr:
                    if isinstance(val, (bytes, bytearray)):
                        s = self._text(val)
                        if s and not s.startswith("http") and len(s) <= 80:
                            candidates.append(s)
            name = candidates[0] if candidates else ""

        remark = self._text(self._first(f, 6)) or self._text(self._first(f, 13))
        year = self._first(f, 14, self._first(f, 13, ""))
        area = self._text(self._first(f, 1))

        return {
            "vod_id": str(vod_id),
            "vod_name": name,
            "vod_pic": cover.get("thumb") or cover.get("path", ""),
            "vod_remarks": remark,
            "vod_year": str(year),
            "vod_area": area
        }

    def _parse_drama_page(self, raw):
        data = self._api_data(raw)
        if not data:
            return []

        try:
            page = self._pb_parse(data)
        except Exception as exc:
            preview = data[:160]
            try:
                preview = preview.decode("utf-8", "ignore")
            except Exception:
                preview = repr(preview)
            raise RuntimeError("列表数据不是 DramaBeanPage: %s %s" % (exc, re.sub(r"\s+", " ", str(preview))[:120]))

        candidates = []
        # 标准 DramaBeanPage.dramaBeanList 是 field 1
        for val in page.get(1, []):
            if isinstance(val, (bytes, bytearray)) and val:
                candidates.append(val)

        videos = []
        seen = set()
        for val in candidates:
            try:
                vod = self._parse_drama(val)
                if vod.get("vod_id") and vod.get("vod_name") and vod["vod_id"] not in seen:
                    videos.append(vod)
                    seen.add(vod["vod_id"])
            except Exception:
                continue
        return videos

    def _parse_video(self, raw):
        f = self._pb_parse(raw)
        return {
            "title": self._text(self._first(f, 2)), "path": self._text(self._first(f, 4)),
            "source": self._text(self._first(f, 9)), "source_cn": self._text(self._first(f, 10))
        }

    # ---------- spider API ----------
    def _static_home(self):
        return {"class": [{"type_id": "25", "type_name": "直播"}], "filters": {}}

    def _load_remote_categories(self):
        if self._remote_classes is not None:
            return self._remote_classes, self._remote_filters

        obj = self._get_json("/api/v3/drama/getCategory?orderBy=type_id")
        classes, filters = [], {}
        raw_items = obj.get("data") or []

        name_map = {
            "class": "分类",
            "lang": "语言",
            "area": "地区",
            "year": "年份",
            "extend_sort": "排序"
        }

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "")
            if name == "公告":
                continue
            tid = str(item.get("id", "") or "")
            if not tid or not name:
                continue

            classes.append({"type_id": tid, "type_name": name})

            raw_filter = item.get("converUrl") or ""
            try:
                ext = json.loads(raw_filter) if isinstance(raw_filter, str) else raw_filter
            except Exception:
                ext = {}

            fl = []
            if isinstance(ext, dict):
                for key in ("class", "lang", "area", "year", "extend_sort"):
                    value = ext.get(key, "")
                    if value:
                        vals = [x for x in str(value).split("|") if x]
                        fl.append({
                            "key": key,
                            "name": name_map.get(key, key),
                            "value": [{"n": x, "v": x} for x in vals]
                        })
            if fl:
                filters[tid] = fl

        if not classes:
            raise RuntimeError("服务器分类为空")

        # 建立静态 1/2/3/4 到真实分类 id 的映射。
        # 优先按名称匹配；匹配不到则按服务器顺序匹配前四个。
        wanted = [
            ("1", ("电影", "电影片", "影片")),
            ("2", ("电视剧", "连续剧", "剧集")),
            ("3", ("综艺",)),
            ("4", ("动漫", "动画"))
        ]
        remote_by_static = {}
        for static_id, names in wanted:
            for c in classes:
                cname = c["type_name"]
                if any(n in cname for n in names):
                    remote_by_static[static_id] = c["type_id"]
                    break

        for index, static_id in enumerate(["1", "2", "3", "4"]):
            if static_id not in remote_by_static and len(classes) > index:
                remote_by_static[static_id] = classes[index]["type_id"]

        # 隐藏明显不是点播的分类，避免“直播”走点播分类接口返回默认列表。
        hidden_words = ("公告",)
        classes = [c for c in classes if not any(w in c.get("type_name", "") for w in hidden_words)]
        valid_ids = set(str(c.get("type_id", "")) for c in classes)
        filters = {k: v for k, v in filters.items() if str(k) in valid_ids}

        # live_only_filter_marker：只保留直播分类，其他全部隐藏。
        live_classes = [c for c in classes if "直播" in str(c.get("type_name", ""))]
        if live_classes:
            classes = live_classes
            live_ids = set(str(c.get("type_id", "")) for c in classes)
            filters = {k: v for k, v in filters.items() if str(k) in live_ids}
        else:
            classes = [{"type_id": "25", "type_name": "直播"}]
            filters = {}

        self._remote_classes = classes
        self._remote_filters = filters
        self._remote_id_by_static = {k: v for k, v in remote_by_static.items() if str(v) in valid_ids}
        self._remote_id_set = valid_ids
        self._remote_name_by_id = {str(c.get("type_id", "")): c.get("type_name", "") for c in classes}
        return classes, filters

    def homeContent(self, filter):
        # 直播专用版：不请求服务器分类，避免服务端返回 HTML 导致 Unexpected token '<'
        return {
            "class": [
                {"type_id": "25", "type_name": "直播"}
            ],
            "filters": {}
        }

    def homeVideoContent(self):
        return {"list": []}

    def _category_id_candidates(self, tid):
        # 直播专用：25 是直播常见分类；0/空参数用于复用之前能出数据的默认直播/推荐列表。
        out = []
        for v in ("25", "0", ""):
            if v not in out:
                out.append(v)
        return out

    def categoryContent(self, tid, pg, filter, extend):
        # 只保留直播分类。不要请求服务器分类接口，直接请求资源接口。
        page = int(pg or 1)
        errors = []

        for real_tid in self._category_id_candidates(tid):
            params = {
                "pagesize": "21",
                "page": str(page),
                "vodOrderBy": "最新"
            }
            # real_tid="" 时不传 typeId1，用于兜底默认列表。
            if str(real_tid) != "":
                params["typeId1"] = str(real_tid)

            try:
                raw = self._post_category(self._secure_body(params))
                videos = self._parse_drama_page(raw)
                if videos:
                    return {
                        "list": videos,
                        "page": page,
                        "pagecount": page + (1 if len(videos) >= 21 else 0),
                        "limit": 21,
                        "total": 999999
                    }
                errors.append("typeId1=%s 返回空" % (real_tid if real_tid != "" else "未传"))
            except Exception as exc:
                errors.append("typeId1=%s %s" % (real_tid if real_tid != "" else "未传", exc))

        return {
            "list": [{
                "vod_id": "error",
                "vod_name": "直播没有数据",
                "vod_pic": "",
                "vod_remarks": re.sub(r"\\s+", " ", "；".join(errors))[:220]
            }],
            "page": page,
            "pagecount": 1,
            "limit": 21,
            "total": 1,
            "error": "；".join(errors)
        }

    def detailContent(self, ids):
        if ids and str(ids[0]) == "error":
            return {"list": []}
        try:
            raw = self._post("/api/proto/v5/drama/getDetail", self._secure_body({"id": str(ids[0])}))
            f = self._pb_parse(self._api_data(raw))
            cover_raw = self._first(f, 2, b"")
            cover = self._parse_cover(cover_raw) if cover_raw else {}
            sources = {}
            for item in f.get(29, []):
                video = self._parse_video(item)
                source = video["source_cn"] or "橘汁"
                path = video["path"]
                if not self.isVideoFormat(path):
                    token = base64.b64encode(json.dumps({"vodPlayFrom": video["source"], "playUrl": path}, ensure_ascii=False, separators=(",", ":")).encode()).decode()
                else:
                    token = path
                sources.setdefault(source, []).append((video["title"] or "播放") + "$" + token)
            vod = {
                "vod_id": str(ids[0]), "vod_name": self._text(self._first(f, 9)),
                "vod_pic": cover.get("path") or cover.get("thumb", ""),
                "vod_actor": self._text(self._first(f, 25)), "vod_director": self._text(self._first(f, 12)),
                "vod_area": self._text(self._first(f, 1)), "vod_year": str(self._first(f, 18, "")),
                "vod_remarks": self._text(self._first(f, 26)), "vod_content": self._text(self._first(f, 6)),
                "vod_play_from": "$$$".join(sources.keys()),
                "vod_play_url": "$$$".join("#".join(v) for v in sources.values())
            }
            return {"list": [vod]}
        except Exception as e:
            return {"list": [], "error": str(e)}

    def searchContent(self, key, quick, pg="1"):
        try:
            raw = self._post("/api/proto/v5/drama/search", self._secure_body({"searchKeys": key, "page": str(pg), "pagesize": "21"}))
            return {"list": self._parse_drama_page(raw)}
        except Exception as e:
            return {"list": [], "error": str(e)}

    def playerContent(self, flag, id, vipFlags):
        try:
            if self.isVideoFormat(id):
                return {"parse": 0, "url": id, "header": {}}
            params = json.loads(base64.b64decode(id).decode("utf-8"))
            raw = self._post("/api/proto/v5/videoUsableUrl", self._secure_body(params))
            f = self._pb_parse(self._api_data(raw))
            headers = {}
            for entry in f.get(6, []):
                ef = self._pb_parse(entry)
                k, v = self._text(self._first(ef, 1)), self._text(self._first(ef, 2))
                if k:
                    headers[k] = v
            return {"parse": 0, "url": self._text(self._first(f, 1)), "header": headers}
        except Exception as e:
            return {"parse": 1, "url": id, "header": {}, "error": str(e)}

    def localProxy(self, param):
        return [404, "text/plain", "", None]
