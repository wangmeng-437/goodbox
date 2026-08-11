# -*- coding: utf-8 -*-
# 本资源来源于互联网公开渠道，仅可用于个人学习及爬虫技术交流。
# 严禁将其用于任何商业用途，下载后请于 24 小时内删除，搜索结果均来自源站，本人不承担任何责任。
"""
{
    "key": "pipixia",
    "name": "皮皮虾影视",
    "type": 3,
    "api": "./皮皮虾toV5改.py",
    "ext": "http://domain.com|你的token值|极速专线>国内高速>蓝光>官方"  # 格式：域名|token|排序关键词>分隔
}
"""
import re,sys,uuid
from base.spider import Spider
sys.path.append('..')
class Spider(Spider):
    host,config,local_uuid,parsing_config = '','','',[]
    # 新增线路排序规则变量
    play_line_sort = []
    # 基础请求头，token和uuid后续动态解析/生成添加
    headers = {
        'User-Agent': "Dart/2.19 (dart:io)",
        'Accept-Encoding': "gzip"
    }
    def init(self, extend=''):
        try:
            # 核心修改：解析ext配置，支持 域名|token|排序关键词>分隔 格式
            self.play_line_sort = []  # 初始化排序规则
            if '|' in extend:
                extend_parts = extend.strip().split('|', 2)  # 只分割2次，适配3段式配置
                host = extend_parts[0].strip()
                # 解析token
                if len(extend_parts) >= 2 and extend_parts[1].strip():
                    token = extend_parts[1].strip()
                    self.headers['token'] = token
                    print(f"✅ 从ext解析到token：{self.headers['token'][:8]}****")
                else:
                    print("⚠️ ext中token未配置，将无token请求")
                # 解析线路排序规则 from：关键词用>分隔
                if len(extend_parts) >= 3 and extend_parts[2].strip():
                    self.play_line_sort = [k.strip() for k in extend_parts[2].split('>') if k.strip()]
                    print(f"✅ 从ext解析到线路排序规则：{self.play_line_sort}")
            else:
                host = extend.strip()
                print("⚠️ ext未配置token和排序规则，格式请按：域名|token|排序关键词>分隔")
            
            # 原域名校验逻辑
            if not host.startswith('http'):
                return {}
            if not re.match(r'^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?/?$', host):
                host_=self.fetch(host).json()
                self.host = host_['domain']
            else:
                self.host = host
            
            # 生成uuid并添加到请求头
            self.local_uuid = str(uuid.uuid4())
            self.headers['appto-local-uuid'] = self.local_uuid
            # 原初始化逻辑：获取配置
            response = self.fetch(f'{self.host}/apptov5/v1/config/get?p=android&__platform=android', headers=self.headers).json()
            config = response['data']
            self.config = config
            parsing_conf = config['get_parsing']['lists']
            parsing_config = {}
            for i in parsing_conf:
                if len(i['config']) != 0:
                    label = []
                    for j in i['config']:
                        if j['type'] == 'json':
                            label.append(j['label'])
                    parsing_config.update({i['key']:label})
            self.parsing_config = parsing_config
            return None
        except Exception as e:
            print(f'初始化异常：{e}')
            return {}

    # 新增：线路排序核心方法，按模糊匹配关键词排序
    def sort_play_lines(self, line_list):
        """
        对播放线路列表按关键词模糊匹配排序
        :param line_list: 原始vod_play_list线路列表
        :return: 排序后的线路列表
        """
        if not self.play_line_sort or not line_list:
            return line_list  # 无排序规则则返回原列表
        
        def get_sort_score(line):
            """获取线路排序分值，分值越低优先级越高"""
            line_name = line.get('player_info', {}).get('show', '').lower()
            # 遍历排序规则，匹配到则返回对应索引（分值）
            for idx, keyword in enumerate(self.play_line_sort):
                if keyword.lower() in line_name:
                    return idx
            # 未匹配到任何关键词，返回规则长度（排最后）
            return len(self.play_line_sort)
        
        # 按分值升序排序，分值相同保留原顺序
        sorted_lines = sorted(line_list, key=lambda x: get_sort_score(x))
        return sorted_lines

    def detailContent(self, ids):
        response = self.fetch(f"{self.host}/apptov5/v1/vod/getVod?id={ids[0]}",headers=self.headers).json()
        data3 = response['data']
        videos = []
        vod_play_url = ''
        vod_play_from = ''
        
        # 核心修改：调用线路排序方法处理原始线路列表
        sorted_play_list = self.sort_play_lines(data3['vod_play_list'])

        # 遍历排序后的线路生成播放链接
        for i in sorted_play_list:
            play_url = ''
            for j in i['urls']:
                play_url += f"{j['name']}${i['player_info']['from']}@{j['url']}#"
            vod_play_from += i['player_info']['show'] + '$$$'
            vod_play_url += play_url.rstrip('#') + '$$$'
        vod_play_url = vod_play_url.rstrip('$$$')
        vod_play_from = vod_play_from.rstrip('$$$')
        videos.append({
            'vod_id': data3.get('vod_id'),
            'vod_name': data3.get('vod_name'),
            'vod_content': data3.get('vod_content'),
            'vod_remarks': data3.get('vod_remarks'),
            'vod_director': data3.get('vod_director'),
            'vod_actor': data3.get('vod_actor'),
            'vod_year': data3.get('vod_year'),
            'vod_area': data3.get('vod_area'),
            'vod_play_from': vod_play_from,
            'vod_play_url': vod_play_url
        })
        return {'list': videos}

    def searchContent(self, key, quick, pg='1'):
        url = f"{self.host}/apptov5/v1/search/lists?wd={key}&page={pg}&type=&__platform=android"
        response = self.fetch(url, headers=self.headers).json()
        data = response['data']['data']
        for i in data:
            if i.get('vod_pic').startswith('mac://'):
                i['vod_pic'] = i['vod_pic'].replace('mac://', 'http://', 1)
        return {'list': data, 'page': pg, 'total': response['data']['total']}

    def playerContent(self, flag, id, vipflags):
        default_ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
        parsing_config = self.parsing_config
        parts = id.split('@')
        if len(parts) != 2:
            return {'parse': 0, 'url': id, 'header': {'User-Agent': default_ua}}
        playfrom, rawurl = parts
        label_list = parsing_config.get(playfrom)
        if not label_list:
            return {'parse': 0, 'url': rawurl, 'header': {'User-Agent': default_ua}}
        result = {'parse': 1, 'url': rawurl, 'header': {'User-Agent': default_ua}}
        for label in label_list:
            payload = {
                'play_url': rawurl,
                'label': label,
                'key': playfrom
            }
            try:
                response = self.post(
                    f"{self.host}/apptov5/v1/parsing/proxy?__platform=android",
                    data=payload,
                    headers=self.headers
                ).json()
            except Exception as e:
                print(f"请求异常: {e}")
                continue
            if not isinstance(response, dict):
                continue
            if response.get('code') == 422:
                continue
            data = response.get('data')
            if not isinstance(data, dict):
                continue
            url = data.get('url')
            if not url:
                continue
            ua = data.get('UA') or data.get('UserAgent') or default_ua
            result = {
                'parse': 0,
                'url': url,
                'header': {'User-Agent': ua}
            }
            break
        return result

    def homeContent(self, filter):
        config = self.config
        if not config:
            return {}
        home_cate = config['get_home_cate']
        classes = []
        for i in home_cate:
            if isinstance(i.get('extend', []),dict):
                classes.append({'type_id': i['cate'], 'type_name': i['title']})
        return {'class': classes}

    def homeVideoContent(self):
        response = self.fetch(f'{self.host}/apptov5/v1/home/data?id=1&mold=1&__platform=android',headers=self.headers).json()
        data = response['data']
        vod_list = []
        for i in data['sections']:
            for j in i['items']:
                vod_pic = j.get('vod_pic')
                if vod_pic.startswith('mac://'):
                    vod_pic = vod_pic.replace('mac://', 'http://', 1)
                vod_list.append({
                    "vod_id": j.get('vod_id'),
                    "vod_name": j.get('vod_name'),
                    "vod_pic": vod_pic,
                    "vod_remarks": j.get('vod_remarks')
                })
        return {'list': vod_list}

    def categoryContent(self, tid, pg, filter, extend):
        response = self.fetch(f"{self.host}/apptov5/v1/vod/lists?area={extend.get('area','')}&lang={extend.get('lang','')}&year={extend.get('year','')}&order={extend.get('sort','time')}&type_id={tid}&type_name=&page={pg}&pageSize=21&__platform=android", headers=self.headers).json()
        data = response['data']
        data2 = data['data']
        for i in data['data']:
            if i.get('vod_pic','').startswith('mac://'):
                i['vod_pic'] = i['vod_pic'].replace('mac://', 'http://', 1)
        return {'list': data2, 'page': pg, 'total': data['total']}

    def getName(self):
        pass
    def isVideoFormat(self, url):
        pass
    def manualVideoCheck(self):
        pass
    def destroy(self):
        pass
    def localProxy(self, param):
        pass
