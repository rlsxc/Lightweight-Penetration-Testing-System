# -*- coding: utf-8 -*-

import os
from pathlib import Path
import json
import requests
import threading
from .randheader import get_ua #用于获取随机的用户代理（User-Agent）和随机的IP地址，以及一个HEADERS字典，其中包含了一些HTTP请求头的常见字段
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
STATUS_CODES = [200, 206, 401, 305, 407]           # HTTP响应状态码，判断认为存在风险链接的状态码
RESULT = []

THREADMAX = threading.BoundedSemaphore(32)    # 限制线程的最大数量为32个


def get_html(url=''):
    """
    判断URL访问是否存在
    """
    if url:
        try:
            response = requests.get(url, headers=get_ua(), timeout=3, allow_redirects=False)
            if response.status_code in STATUS_CODES:
                return True
        except Exception as e:
            pass
    else:
        return False


def get_html2(url='', key=''):
    """
    判断URL访问是否存在，用于多线程
    """
    if url:
        try:
            response = requests.get(url, headers=get_ua(), timeout=3, allow_redirects=False, verify=False)
            if response.status_code in STATUS_CODES:
                RESULT.append([key, url])
        except Exception as e:
            pass
    THREADMAX.release()


def get_infoleak(url=''):
    """
    尝试访问风险链接
    """
    global RESULT
    RESULT = []         #清空
    BASE_DIR = Path(__file__).resolve().parent.parent
    file_path = os.path.join(BASE_DIR,'database','infoleak.json')
    with open(file_path,mode='r',encoding='utf-8') as fp:# 配置文件 database/infoleak.json
        json_data = json.load(fp)
    payload_list = []
    thread_list = []

    for key in json_data['data'][0]:
        payloads = json_data['data'][0][key]
        for payload in payloads:
            # 开始尝试访问
            url_payload = url + payload
            payload_list.append([key, url_payload])
            # if get_html(url_payload):
            #     result.append([key, url_payload])

    """
        由于，线程不能无限增加
        远程站点，也会限制并发数
        所以这里需要设置线程数为50
        因为需要扫描的规则比较多
        针对超时或者没获取到的，不加入结果列表
    """

    for item in payload_list:
        THREADMAX.acquire()
        thd = threading.Thread(target=get_html2, args=(item[1], item[0], ))
        thd.start()
        thread_list.append(thd)

    for thd in thread_list:
        thd.join()

    return RESULT


if __name__ == '__main__':
    print(get_infoleak())
