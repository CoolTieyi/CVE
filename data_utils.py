import logging
from collections import defaultdict
from typing import Iterator, Dict
import scrapy
import json
import pandas as pd

logging.basicConfig(level=logging.DEBUG  # 设置日志输出格式
                    , filename="demo_trivy_2.log"  # log日志输出的文件位置和文件名
                    # ,filemode="w" #文件的写入格式，w为重新写入文件，默认是追加
                    # ,format="%(asctime)s - %(name)s - %(levelname)-9s - %(filename)-8s : %(lineno)s line - %(message)s" #日志输出的格式
                    # -8表示占位符，让输出左对齐，输出长度都为8位
                    # ,datefmt="%Y-%m-%d %H:%M:%S" #时间输出的格式
                    )


def group_by(cve_datas, selector):
    assert callable(selector)
    result = defaultdict(list)
    for cve_data in cve_datas:
        result[selector(cve_data)].append(cve_data)
    return result


def first_of(*items):
    for item in items:
        if len(item) > 0:
            assert len(item) == 1
            return item[0]
    raise f"all of items are empty: {items}"


def resolve_nested_dict(dict_data, keys) -> str | None:
    if len(keys) == 0:
        return None
    key = keys[0]
    if key not in dict_data:
        return None
    if len(keys) == 1:
        return dict_data[key]
    return resolve_nested_dict(dict_data[key], keys[1:])


def iter_nested_dict(dict_data, keys) -> Iterator[Dict]:
    """
    e.g.
    "a": [
        {
            "b": [
                {
                    "target_key": "value"
                },
                ...
            ]
        },
        {
            "b": [
                {
                    "target_key": "value"
                },
                ...
            ]
        },
    ]

    iter_nested_dict(json_data, ["a", "b"])
    would iter through all the dicts:
    {
        "target_key": "value"
    }
    """
    if isinstance(dict_data, list):
        for item in dict_data:
            yield from iter_nested_dict(item, keys)
        return

    if len(keys) == 0:
        return
    key, rest_keys = keys[0], keys[1:]
    if key not in dict_data:
        return
    res = dict_data[key]
    if len(rest_keys) == 0:
        if isinstance(res, list):
            yield from res
        else:
            yield res
    else:
        yield from iter_nested_dict(res, rest_keys)


# def get_nvd_version(cveId:str) -> str:
#     url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+cveId
#     json_rsc = requests.get(url)
#     try:
#         json_data = json_rsc.json()
#     except requests.exceptions.JSONDecodeError as e:
#         print(f'url: {url}, response: {json_rsc}')
#         raise e
#
#     match = []
#     for cpe_match in iter_nested_dict(json_data, ['vulnerabilities', 'cve', "configurations", "nodes", "cpeMatch"]):
#         if 'versionStartIncluding' in cpe_match and 'versionEndExcluding' in cpe_match:
#             match.append((cpe_match.get('versionStartIncluding') + " ~ " + cpe_match.get('versionEndExcluding')))
#         elif 'versionStartIncluding' not in cpe_match and 'versionEndExcluding' in cpe_match:
#             match.append(("0" + " ~ " + cpe_match.get('versionEndExcluding')))
#     payload = '; '.join(match)
#
#     return payload


def version_format(s):
    # filter :
    # version_dict
    vdict = defaultdict()
    if s is None or len(s) == 0:
        return None
    if s[0] == 'v':
        vdict['rubbish'] = 'v'
        s = s[1:]

    if ':' in s:
        colon = s.find(':')
        vdict['epoch'] = s[:colon]
        s = s[(colon + 1):]
    else:
        vdict['epoch'] = 0
    # filter -~+
    symbol_position = len(s)
    vdict['semantic'] = s
    vdict['predeta'] = None
    if '+' in s or '-' in s or '~' in s:
        symbol_plus = s.find('+')
        short_line = s.find('-')
        surf_line = s.find('~')
        position = []
        for i in [symbol_plus, short_line, surf_line]:
            if i >= 0:
                position.append(i)
        symbol_position = min(position)
        vdict['semantic'] = s[:symbol_position]
        vdict['predeta'] = s[symbol_position + 1:]
    if vdict['predeta'] is not None and len(vdict['predeta']) != 0:
        vdict['semantic'] = '< ' + vdict['semantic']

    return vdict['semantic']


class NvdSpider(scrapy.Spider):
    data = {}
    handle_httpstatus_lsit = [403]
    name = 'nvd'
    custom_settings = {
        # 'CONCURRENT_REQUESTS': 5,  # 同时请求的数量
        'RETRY_ENABLED': True,
        'RETRY_TIMES': 10,
        'RETRY_HTTP_CODES': [400, 403, 408, 500, 502, 503, 504],
        'AUTOTHROTTLE_ENABLED': True,
        'AUTOTHROTTLE_START_DELAY': 10.0,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 2,
        'DOWNLOAD_DELAY': 10,
        'HTTPCACHE_ENABLED': True,
        'HTTPCACHE_EXPIRATION_SECS': 0,
        'HTTPCACHE_DIR': 'httpcache',
        'HTTPCACHE_IGNORE_HTTP_CODES': [],
        'HTTPCACHE_STORAGE': 'scrapy.extensions.httpcache.FilesystemCacheStorage',
        'DEFAULT_REQUEST_HEADERS': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0',
        },

        # 'DOWNLOADER_MIDDLEWARES':{
        #     'askdoctor.middlewares.AskdoctorDownloaderMiddleware':543,
        # },
    }

    def __init__(self, cve_data: list):
        super(NvdSpider, self).__init__()
        self.cve_data = cve_data
        self.cache = defaultdict()

    def start_requests(self):
        for cve in self.cve_data:
            url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + cve.CVEId
            yield scrapy.Request(url=url, callback=self.parse, dont_filter= True,cb_kwargs={'cve': cve})

    def parse(self, response, **kwargs):
        cve = kwargs['cve']

        if response.status == 403 or response.status == 503 :
            print(response.status," !!! ", cve.CVEId)
        else:
            NvdSpider.data = json.loads(response.text)
            match = []
            for cpe_match in iter_nested_dict(NvdSpider.data,
                                              ['vulnerabilities', 'cve', "configurations", "nodes", "cpeMatch"]):
                if 'versionStartIncluding' in cpe_match and 'versionEndExcluding' in cpe_match:
                    match.append(
                        ("[" + cpe_match.get('versionStartIncluding') + "," + cpe_match.get(
                            'versionEndExcluding') + ")"))
                elif 'versionStartIncluding' not in cpe_match and 'versionEndExcluding' in cpe_match:
                    match.append(("[0" + "," + cpe_match.get('versionEndExcluding') + ")"))
                elif 'versionEndIncluding' in cpe_match:
                    match.append(("[0" + "," + cpe_match.get('versionEndIncluding') + "]"))
            res = ' ; '.join(match)
            cve.nvd_version = res
            logging.info(cve.CVEId + " ______________________________ " + cve.nvd_version)
            print(response.status, cve.CVEId + " ______________________________ " + cve.nvd_version)
