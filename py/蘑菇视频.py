# coding=utf-8
import sys
import json
import base64
import re
import hashlib
import urllib.parse
sys.path.append('..')
try:
    from base.spider import Spider
except Exception:
    class Spider(object):
        pass

class Spider(Spider):
    host = "https://8.136.14.184"

    SEARCH_ALIASES = {
        "原创热点": "原创",
        "萝莉少女": "萝莉",
        "性虐调教": "调教",
        "国产自拍": "国产",
        "大奶聚集地": "巨乳",
        "勾引搭讪": "搭讪",
        "网红尤物": "网红",
        "花样百出": "花样",
        "户外野战": "户外",
        "人性沦丧": "迷奸",
        "媚黑激战": "黑人",
        "本站原创": "原创",
        "用户自拍": "自拍",
        "外流偷拍": "偷拍",
        "直播录播": "直播",
        "女子spa": "SPA",
        "华人AV": "华人",
        "日韩AV": "日韩",
        "欧美AV": "欧美",
        "国产AV": "国产",
        "其他自制AV": "自制",
        "国产三级片": "三级",
        "A I 猎奇": "猎奇",
        "高清有码": "有码",
        "中字有码": "有码",
        "COS性爱": "COS",
        "多人多p": "多人",
        "日韩三级片": "三级",
        "黛西宝贝": "黛西",
        "桃子派": "桃子",
        "中字动漫": "动漫",
        "里番动漫": "里番",
        "欧美up": "欧美",
        "黑人专栏": "黑人",
        "捷克接头搭讪": "捷克",
        "欧美杂类": "欧美",
        "思春社": "思春",
        "ed是什么": "ED",
        "知识科普": "科普",
        "人间炼狱": "缅北",
        "暗网媒体稀缺资源": "暗网",
        "恐怖情色": "恐怖",
        "恶心恐怖": "恐怖",
        "灵异玄幻": "灵异",
    }

    def getName(self):
        return "py_蘑菇视频"

    def init(self, extend=""):
        self.header = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Pixel 6) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/132.0.0.0 Mobile Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
        }
        self.type_names = {}
        self.subtype_names = {}

    def isVideoFormat(self, url):
        return bool(url) and ('.m3u8' in url or '.plist' in url)

    def manualVideoCheck(self):
        pass

    def destroy(self):
        pass

    def _fetch_json(self, url):
        try:
            resp = self.fetch(url, headers=self.header)
            text = resp.content.decode('utf-8')
            return json.loads(text)
        except Exception as e:
            print("[py_蘑菇视频] 请求失败:", e)
            return {}

    def _fetch_text(self, url):
        try:
            resp = self.fetch(url, headers=self.header)
            return resp.content.decode('utf-8')
        except Exception as e:
            print("[py_蘑菇视频] 请求失败:", e)
            return ""

    def _decrypt_image(self, data, pic_url):
        if len(data) < 16:
            return data
        if data[0] == 0xff and data[1] == 0xd8:
            return data
        from urllib.parse import urlparse, unquote
        parsed = urlparse(pic_url)
        filename = unquote(parsed.path.split('/')[-1])
        key = hashlib.md5(filename.encode()).digest()
        iv = key
        try:
            from Crypto.Cipher import AES
            pad_len = (16 - len(data) % 16) % 16
            padded = data + b'\x00' * pad_len
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(padded)[:len(data)]
            if decrypted[:2] == b'\xff\xd8':
                return decrypted
        except Exception:
            pass
        key_xor = bytes([data[i] ^ b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01'[i] for i in range(16)])
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key_xor[i % 16]
        return bytes(result)

    def _proxy_url(self, url, ptype="img"):
        if not url:
            return ""
        encoded = base64.urlsafe_b64encode(url.encode()).decode()
        return "http://127.0.0.1:9978/proxy?do={0}&url={1}&type={2}".format(
            self.getName(), encoded, ptype)

    def _get_m3u8_url(self, play_url):
        if not play_url:
            return ""
        parts = play_url.split('?')
        if len(parts) == 2:
            return parts[0] + '.m3u8?' + parts[1]
        return play_url + '.m3u8'

    def _get_search_key(self, name):
        if name in self.SEARCH_ALIASES:
            return self.SEARCH_ALIASES[name]
        base_name = name.split("-")[0].split("—")[0].strip()
        if base_name in self.SEARCH_ALIASES:
            return self.SEARCH_ALIASES[base_name]
        for suffix in ["AV", "片", "视频", "热点", "专区", "大全", "聚集地"]:
            if name.endswith(suffix) and len(name) > len(suffix):
                short = name[:-len(suffix)]
                if short in self.SEARCH_ALIASES:
                    return self.SEARCH_ALIASES[short]
                return short
        if base_name != name:
            return base_name
        return name

    def _parse_items(self, items):
        vlist = []
        for it in items:
            vid = str(it.get("id", ""))
            name = it.get("title", "")
            pic = it.get("cover", "")
            if pic:
                pic = self._proxy_url(pic, "img")
            vlist.append({
                "vod_id": vid,
                "vod_name": name,
                "vod_pic": pic,
                "vod_year": "",
                "vod_area": "",
                "vod_remarks": "",
                "vod_director": "",
                "vod_actor": "",
                "vod_content": "",
            })
        return vlist

    def homeContent(self, filter):
        data = self._fetch_json(self.host + "/api/vod/type")
        classes = []
        filters = {}
        self.type_names = {}
        self.subtype_names = {}
        if data.get("code") == 200:
            type_list = data.get("data", {}).get("list", [])
            for t in type_list:
                type_id = str(t.get("id", ""))
                type_name = t.get("name", "")
                self.type_names[type_id] = type_name
                classes.append({"type_id": type_id, "type_name": type_name})
                child_list = t.get("child", [])
                if child_list:
                    filter_items = [{"n": "全部", "v": type_id}]
                    for c in child_list:
                        c_id = str(c.get("id", ""))
                        c_name = c.get("name", "")
                        self.subtype_names[c_id] = c_name
                        filter_items.append({"n": c_name, "v": c_id})
                    filters[type_id] = [{"key": "subtype", "name": "分类", "value": filter_items}]
        return {"class": classes, "filters": filters}

    def homeVideoContent(self):
        data = self._fetch_json(self.host + "/api/vod/list?page=1")
        items = data.get("data", {}).get("list", []) if isinstance(data, dict) else []
        return {"list": self._parse_items(items)}

    def categoryContent(self, tid, pg, filter, extend):
        search_key = self.type_names.get(tid, "")
        if extend and isinstance(extend, dict):
            subtype = extend.get("subtype", "")
            if subtype and subtype != tid:
                subtype_name = self.subtype_names.get(subtype, "")
                if subtype_name:
                    search_key = subtype_name
        search_key = self._get_search_key(search_key)
        if not search_key:
            return {"list": [], "page": int(pg), "pagecount": 0, "limit": 20, "total": 0}
        url = "{0}/api/vod/clever?wd={1}&limit=20&page={2}".format(
            self.host, urllib.parse.quote(search_key), pg)
        data = self._fetch_json(url)
        items = data.get("data", {}).get("list", []) if isinstance(data, dict) else []
        total = data.get("data", {}).get("total", 999999) if isinstance(data, dict) else 999999
        return {
            "list": self._parse_items(items),
            "page": int(pg),
            "pagecount": 9999,
            "limit": 20,
            "total": total,
        }

    def searchContent(self, key, quick, pg="1"):
        if not key:
            return {"list": [], "page": int(pg), "pagecount": 0, "limit": 20, "total": 0}
        url = "{0}/api/vod/clever?wd={1}&limit=20&page={2}".format(
            self.host, urllib.parse.quote(key), pg)
        data = self._fetch_json(url)
        items = data.get("data", {}).get("list", []) if isinstance(data, dict) else []
        return {
            "list": self._parse_items(items),
            "page": int(pg),
            "pagecount": 9999,
            "limit": 20,
            "total": 999999,
        }

    def detailContent(self, ids):
        if not ids:
            return {"list": []}
        vid = ids[0]
        url = "{0}/api/vod/info?id={1}".format(self.host, vid)
        data = self._fetch_json(url)
        if data.get("code") != 200:
            return {"list": []}
        info = data.get("data", {})
        play_url = info.get("play_url", "")
        pic = info.get("cover", "")
        if pic:
            pic = self._proxy_url(pic, "img")
        labels = info.get("labels", [])
        label_names = ",".join([l.get("name", "") for l in labels]) if labels else ""
        m3u8_url = self._get_m3u8_url(play_url) if play_url else ""
        return {"list": [{
            "vod_id": str(info.get("id", "")),
            "vod_name": info.get("title", ""),
            "vod_pic": pic,
            "vod_year": "",
            "vod_area": "",
            "vod_remarks": "",
            "vod_director": "",
            "vod_actor": "",
            "vod_content": label_names or info.get("title", ""),
            "vod_play_from": "蘑菇视频",
            "vod_play_url": "正片${0}".format(m3u8_url),
        }]}

    def playerContent(self, flag, id, vipFlags):
        return {
            "parse": 0,
            "url": id,
            "header": json.dumps(self.header, ensure_ascii=False),
        }

    def localProxy(self, param):
        url = base64.urlsafe_b64decode(param.get('url', '')).decode()
        ptype = param.get('type', '')
        if ptype == 'img':
            resp = self.fetch(url, headers=self.header)
            data = resp.content
            decrypted = self._decrypt_image(data, url)
            return [200, "image/jpeg", decrypted]
        return [200, "text/plain", b'']
