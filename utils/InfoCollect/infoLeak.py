# -*- coding: utf-8 -*-

import os
from pathlib import Path
import json
import requests
import threading
from .randheader import get_ua  # 用于获取随机的用户代理（User-Agent）和随机的IP地址，以及一个HEADERS字典
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 扩展状态码，捕获更多可能的泄露路径
STATUS_CODES = [200, 206, 401, 403, 305, 407]  # 添加 403 以检测未授权访问的路径
RESULT = []

# 限制线程的最大数量为 32 个
THREADMAX = threading.BoundedSemaphore(32)


def get_html(url=''):
    """
    判断URL访问是否存在
    """
    if url:
        try:
            response = requests.get(url, headers=get_ua(), timeout=5, allow_redirects=False)
            if response.status_code in STATUS_CODES:
                return True
        except Exception as e:
            print(f"Error in get_html for {url}: {str(e)}")
    else:
        return False


def get_html2(url='', key=''):
    """
    判断URL访问是否存在，用于多线程
    """
    if url:
        try:
            # 确保 URL 以 http:// 或 https:// 开头
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            print(f"Attempting request to: {url}")
            response = requests.get(url, headers=get_ua(), timeout=5, allow_redirects=False, verify=False)
            print(f"URL: {url}, Status: {response.status_code}")
            if response.status_code in STATUS_CODES:
                print(f"Match found: {key} -> {url}")
                RESULT.append([key, url])
            else:
                print(f"URL {url} skipped, status {response.status_code} not in {STATUS_CODES}")
        except Exception as e:
            print(f"Error for {url}: {str(e)}")
        finally:
            THREADMAX.release()


def get_infoleak(url=''):
    """
    尝试访问风险链接
    """
    global RESULT
    RESULT = []  # 清空
    BASE_DIR = Path(__file__).resolve().parent.parent
    file_path = os.path.join(BASE_DIR, 'database', 'infoleak.json')

    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found")
        return RESULT

    try:
        with open(file_path, mode='r', encoding='utf-8') as fp:
            json_data = json.load(fp)
            print(f"Loaded payloads: {json_data['data'][0].keys()}")
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        return RESULT

    payload_list = []
    thread_list = []

    # 确保输入 URL 包含协议
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    print(f"Processing URL: {url}")

    for key in json_data['data'][0]:
        payloads = json_data['data'][0][key]
        for payload in payloads:
            # 构造完整 URL，移除多余斜杠
            url_payload = url.rstrip('/') + payload
            payload_list.append([key, url_payload])

    """
    由于线程不能无限增加，且远程站点可能限制并发数，
    这里设置线程数为32，针对超时或未获取到的，不加入结果列表
    """
    for item in payload_list:
        THREADMAX.acquire()
        thd = threading.Thread(target=get_html2, args=(item[1], item[0],))
        thd.start()
        thread_list.append(thd)

    for thd in thread_list:
        thd.join()

    if not RESULT:
        print(f"No information leakage detected for {url}")
    return RESULT


if __name__ == '__main__':
    # 测试示例 URL
    print(get_infoleak('https://httpbin.org/'))
