# coding=utf-8
import sys
import json
import base64
import re
import hashlib
import time
import urllib.parse
sys.path.append('..')
try:
    from base.spider import Spider
except Exception:
    class Spider(object):
        pass

class Spider(Spider):
    host = "https://3061366074.w1.xhsr9m1f.cc:2024"
    SECRET_KEY = "UC2FmMyG928hRZY4"
    API_KEY = "WB0nMZHXlxNndORe"
    SIGN_SECRET = "Hdg0TH2WzxsYRSeR4cX71ovnWUN7ae"
    CDN_SIGN_SECRET = "psIBMQo9fjm2xlL6Vpr3IsQ8dWHS46"

    def getName(self):
        return "py_小黄书"

    def init(self, extend=""):
        self.header = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Pixel 6) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/132.0.0.0 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        self.img_domain = ""
        self.imgcover_domain = ""
        self._site_data = None

    def _xor_decrypt(self, encrypted_data):
        import zlib
        token_fixed = encrypted_data.replace('-', '+').replace('_', '/')
        pad = len(token_fixed) % 4
        if pad:
            token_fixed += '=' * (4 - pad)
        raw = base64.b64decode(token_fixed)
        key_bytes = self.SECRET_KEY.encode('utf-8')
        payload = bytearray(len(raw))
        kl = len(key_bytes)
        for i in range(len(raw)):
            payload[i] = raw[i] ^ key_bytes[i % kl]
        flag = payload[0]
        body = payload[1:]
        if flag == 0x01:
            plain = zlib.decompress(bytes(body), -15)
        else:
            plain = bytes(body)
        return json.loads(plain.decode('utf-8'))

    def _decrypt_page_data(self, html):
        try:
            pattern = r"var\s+_0x\w+\s*=\s*'([A-Za-z0-9_\-+=/]+)'\s*;.*?var\s+_0x\w+\s*=\s*(0x[0-9a-fA-F]+)"
            match = re.search(pattern, html, re.DOTALL)
            if not match:
                return None
            token = match.group(1)
            xor_key = int(match.group(2), 16)
            raw = base64.b64decode(token)
            decrypted_html = bytes([b ^ xor_key for b in raw])
            text = urllib.parse.unquote(decrypted_html.decode('latin-1'))
            match2 = re.search(r"new\s+APP\.\w+\('([A-Za-z0-9_\-+=/]+)'\)", text)
            if match2:
                return self._xor_decrypt(match2.group(1))
            match3 = re.search(r"var\s+json\s*=\s*'([A-Za-z0-9_\-+=/]+)'", text)
            if match3:
                return self._xor_decrypt(match3.group(1))
            return None
        except Exception as e:
            print("[py_小黄书] 解密页面数据失败:", e)
            return None

    def _fetch_page(self, path):
        import requests
        requests.packages.urllib3.disable_warnings()
        url = self.host + path
        resp = requests.get(url, headers=self.header, verify=False, timeout=15)
        html = resp.text
        return self._decrypt_page_data(html)

    def _get_pic_url(self, pic):
        if not pic:
            return ""
        if pic.startswith("http"):
            return pic
        domain = self.imgcover_domain or self.img_domain
        if domain:
            return domain + pic
        return self.host + "/" + pic

    def _ensure_site_data(self):
        if self._site_data:
            return self._site_data
        data = self._fetch_page("/")
        if data:
            self._site_data = data
            self.img_domain = data.get("site", {}).get("img_domain", "")
            self.imgcover_domain = data.get("site", {}).get("imgcover_domain", "")
        return self._site_data

    def _batch_get_pics(self, url_list):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        result_map = {}
        valid_urls = {}
        for idx, url in enumerate(url_list):
            if url:
                if url.startswith("//"):
                    url = "https:" + url
                valid_urls[idx] = url
        if not valid_urls:
            return result_map
        def download(idx, url):
            try:
                import requests
                requests.packages.urllib3.disable_warnings()
                resp = requests.get(url, headers=self.header, verify=False, timeout=10)
                img_data = resp.content
                img_data = bytes([b ^ 0x88 for b in img_data])
                mime = 'image/jpeg'
                if img_data[:8] == b'\x89PNG\r\n\x1a\n':
                    mime = 'image/png'
                elif img_data[:4] == b'GIF8':
                    mime = 'image/gif'
                elif img_data[:4] == b'RIFF' and img_data[8:12] == b'WEBP':
                    mime = 'image/webp'
                b64 = base64.b64encode(img_data).decode()
                return idx, "data:" + mime + ";base64," + b64
            except:
                return idx, url
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(download, idx, url): idx for idx, url in valid_urls.items()}
            for future in as_completed(futures):
                idx, pic = future.result()
                result_map[idx] = pic
        return result_map

    def _sign_cdn_url(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
            timestamp = int(time.time())
            sign_source = self.CDN_SIGN_SECRET + parsed.path + str(timestamp)
            sign = hashlib.md5(sign_source.encode('utf-8')).hexdigest()
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params['sign'] = sign
            params['t'] = str(timestamp)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
        except:
            return url

    def _parse_play_url(self, play_url_data):
        play_from = ""
        play_url = ""
        if isinstance(play_url_data, list):
            for source in play_url_data:
                key = source.get("key", source.get("name", ""))
                items = source.get("list", [])
                for item in items:
                    ep_name = item.get("name", "")
                    ep_url = item.get("h264", "") or item.get("url", "")
                    if ep_url:
                        ep_url = self._sign_cdn_url(ep_url)
                        play_from += key + "$$$"
                        play_url += ep_name + "$" + ep_url + "#"
            if play_from.endswith("$$$"):
                play_from = play_from[:-3]
            if play_url.endswith("#"):
                play_url = play_url[:-1]
        elif isinstance(play_url_data, str) and play_url_data:
            play_from = "小黄书"
            play_url = play_url_data
        return play_from, play_url

    def isVideoFormat(self, url):
        pass

    def manualVideoCheck(self):
        pass

    def homeContent(self, filter):
        data = self._ensure_site_data()
        if not data:
            return {"class": []}
        classes = []
        filters = {}
        menu = data.get("menu", [])
        for item in menu:
            mid = item.get("id", item.get("mid", 0))
            name = item.get("name", "")
            if mid == 0:
                continue
            jumpurl = item.get("jumpurl", "")
            if jumpurl and jumpurl.startswith("http"):
                continue
            classes.append({"type_id": str(mid), "type_name": name})
        return {"class": classes, "filters": filters}

    def homeVideoContent(self):
        data = self._ensure_site_data()
        if not data:
            return {'list': []}
        videos = []
        pic_urls = []
        new_vod = data.get("new_vod", {})
        if isinstance(new_vod, dict):
            new_list = new_vod.get("list", [])
            if not new_list and new_vod.get("vod_id"):
                new_list = [new_vod]
            for v in new_list[:3]:
                vid = v.get("vod_id", 0)
                if vid == -1:
                    continue
                pic = self._get_pic_url(v.get("vod_pic", ""))
                pic_urls.append(pic)
                videos.append({
                    "vod_id": str(vid),
                    "vod_name": v.get("vod_name", ""),
                    "vod_pic": pic,
                    "vod_remarks": v.get("vod_duration", "")
                })
        type_data = data.get("type", [])
        if isinstance(type_data, list):
            for t in type_data:
                if not isinstance(t, dict):
                    continue
                tdata = t.get("data", {})
                if not isinstance(tdata, dict):
                    continue
                vlist = tdata.get("list", [])
                for v in vlist[:2]:
                    vid = v.get("vod_id", 0)
                    if vid == -1:
                        continue
                    pic = self._get_pic_url(v.get("vod_pic", ""))
                    pic_urls.append(pic)
                    videos.append({
                        "vod_id": str(vid),
                        "vod_name": v.get("vod_name", ""),
                        "vod_pic": pic,
                        "vod_remarks": v.get("vod_duration", "")
                    })
        vod = data.get("vod", {})
        if isinstance(vod, dict):
            vlist = vod.get("list", [])
            for v in vlist[:3]:
                vid = v.get("vod_id", 0)
                if vid == -1:
                    continue
                pic = self._get_pic_url(v.get("vod_pic", ""))
                pic_urls.append(pic)
                videos.append({
                    "vod_id": str(vid),
                    "vod_name": v.get("vod_name", ""),
                    "vod_pic": pic,
                    "vod_remarks": v.get("vod_duration", "")
                })
        gua = data.get("gua", {})
        if isinstance(gua, dict):
            glist = gua.get("list", [])
            for g in glist[:2]:
                pic = self._get_pic_url(g.get("art_pic", ""))
                pic_urls.append(pic)
                videos.append({
                    "vod_id": "art_" + str(g.get("art_id", "")),
                    "vod_name": g.get("art_name", ""),
                    "vod_pic": pic,
                    "vod_remarks": ""
                })
        pic_map = self._batch_get_pics(pic_urls)
        for i, v in enumerate(videos):
            if i in pic_map:
                v["vod_pic"] = pic_map[i]
        return {'list': videos}

    def categoryContent(self, cid, pg, filter, ext):
        videos = []
        page_num = int(pg)
        pic_urls = []
        if cid == "9":
            data = self._fetch_page("/pbbIdIVx44/9/" + str(page_num))
            if data:
                glist = data.get("list", [])
                for g in glist:
                    pic = self._get_pic_url(g.get("art_pic", ""))
                    pic_urls.append(pic)
                    videos.append({
                        "vod_id": "art_" + str(g.get("art_id", "")),
                        "vod_name": g.get("art_name", ""),
                        "vod_pic": pic,
                        "vod_remarks": ""
                    })
        else:
            data = self._fetch_page("/pbbIdIVx44/" + cid + "/" + str(page_num))
            if data:
                vlist = data.get("list", [])
                for v in vlist:
                    vid = v.get("vod_id", 0)
                    if vid == -1:
                        continue
                    pic = self._get_pic_url(v.get("vod_pic", ""))
                    pic_urls.append(pic)
                    videos.append({
                        "vod_id": str(vid),
                        "vod_name": v.get("vod_name", ""),
                        "vod_pic": pic,
                        "vod_remarks": v.get("vod_duration", "")
                    })
        pic_map = self._batch_get_pics(pic_urls)
        for i, v in enumerate(videos):
            if i in pic_map:
                v["vod_pic"] = pic_map[i]
        result = {'list': videos}
        result['page'] = pg
        result['pagecount'] = 9999
        result['limit'] = 20
        result['total'] = 999999
        return result

    def detailContent(self, ids):
        did = ids[0]
        videos = []
        if did.startswith("art_"):
            art_id = did.replace("art_", "")
            data = self._fetch_page("/6xsjWNAsbm/AN6zAX3A/" + art_id)
            if data:
                details = data.get("details", {})
                if not details:
                    return {'list': []}
                pic = self._get_pic_url(details.get("art_pic", ""))
                name = details.get("art_name", "")
                content = details.get("art_content", "")
                play_from = ""
                play_url = ""
                vod_data_tmp = details.get("vod_data_tmp", {})
                if isinstance(vod_data_tmp, dict) and "0" in vod_data_tmp:
                    v0 = vod_data_tmp["0"]
                    play_url_list = v0.get("vod_play_url", [])
                    play_from, play_url = self._parse_play_url(play_url_list)
                if not play_url and content:
                    images = re.findall(r'src="([^"]*)"', content)
                    if images:
                        for img in images:
                            img_url = img if img.startswith("http") else self._get_pic_url(img)
                            play_url += "图片$" + img_url + "#"
                        play_url = play_url[:-1]
                        play_from = "图片"
                videos.append({
                    "vod_id": did,
                    "vod_name": name,
                    "vod_pic": pic,
                    "vod_content": content,
                    "vod_play_from": play_from or "小黄书",
                    "vod_play_url": play_url
                })
            result = {'list': videos}
            return result
        data = self._fetch_page("/video/" + did)
        if not data:
            return {'list': []}
        info = data.get("info", {})
        if not info:
            return {'list': []}
        pic = self._get_pic_url(info.get("vod_pic", ""))
        name = info.get("vod_name", "")
        content = info.get("vod_blurb", "") or info.get("vod_content", "")
        play_url_data = info.get("vod_play_url", [])
        play_from, play_url = self._parse_play_url(play_url_data)
        if not play_url:
            vod_data_array = info.get("vod_data_array", {})
            if isinstance(vod_data_array, dict):
                play_url_data2 = vod_data_array.get("vod_play_url", [])
                play_from, play_url = self._parse_play_url(play_url_data2)
        videos.append({
            "vod_id": str(info.get("vod_id", did)),
            "vod_name": name,
            "vod_pic": pic,
            "vod_content": content,
            "vod_play_from": play_from or "小黄书",
            "vod_play_url": play_url
        })
        result = {'list': videos}
        return result

    def playerContent(self, flag, id, vipFlags):
        return {
            'jx': 0,
            'parse': 0,
            'url': id,
            'header': {
                "User-Agent": "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
                "Referer": self.host + "/"
            }
        }

    def _fetch_search_html(self, keyword, page):
        import requests
        requests.packages.urllib3.disable_warnings()
        path = "/8Wp3usLwJV/pn00AsjDG/" + urllib.parse.quote(keyword) + "/" + str(page)
        url = self.host + path
        resp = requests.get(url, headers=self.header, verify=False, timeout=15)
        html = resp.text
        pattern = r"var\s+_0x\w+\s*=\s*'([A-Za-z0-9_\-+=/]+)'\s*;.*?var\s+_0x\w+\s*=\s*(0x[0-9a-fA-F]+)"
        match = re.search(pattern, html, re.DOTALL)
        if not match:
            return ""
        token = match.group(1)
        xor_key = int(match.group(2), 16)
        raw = base64.b64decode(token)
        decrypted_html = bytes([b ^ xor_key for b in raw])
        text = urllib.parse.unquote(decrypted_html.decode('latin-1'))
        return text

    def searchContent(self, key, quick, pg="1"):
        videos = []
        pic_urls = []
        page_num = int(pg)
        try:
            text = self._fetch_search_html(key, page_num)
            if not text:
                return {'list': []}
            pattern = r"redirect_vod\('(\d+)'\)[\s\S]*?data-original=\"([^\"]+)\"[\s\S]*?wlegiji3hgi2489rghu[^>]*>([\s\S]*?)</div>"
            matches = re.findall(pattern, text)
            for vod_id, pic, name in matches:
                pic = pic if pic.startswith("http") else self._get_pic_url(pic)
                pic_urls.append(pic)
                videos.append({
                    "vod_id": str(vod_id),
                    "vod_name": name.strip(),
                    "vod_pic": pic,
                    "vod_remarks": ""
                })
        except Exception as e:
            print("[py_小黄书] 搜索失败:", e)
        pic_map = self._batch_get_pics(pic_urls)
        for i, v in enumerate(videos):
            if i in pic_map:
                v["vod_pic"] = pic_map[i]
        result = {'list': videos}
        result['page'] = pg
        result['pagecount'] = 9999
        result['limit'] = 20
        result['total'] = 999999
        return result

    def localProxy(self, param):
        url = base64.urlsafe_b64decode(param.get('url', '')).decode()
        ptype = param.get('type', '')
        if ptype == 'img':
            import requests
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(url, headers=self.header, verify=False, timeout=15)
            return [200, resp.headers.get('Content-Type', 'image/jpeg'), resp.content]
        return [200, "text/plain", b'']
