# -*- coding: utf-8 -*-
# 依赖：fake-useragent 库 (pip3 install fake-useragent)

import random
import socket
import struct
from fake_useragent import UserAgent


def is_private_ip(ip):
    """
    检查给定的 IP 地址是否为私有 IP。
    返回：True（私有）或 False（公共）。
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return True  # 无效 IP
    try:
        a, b, c, d = map(int, parts)
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        return False
    except ValueError:
        return True  # 无效 IP


def get_ua():
    """
    生成并返回包含随机 User-Agent 和 IP 地址的 HTTP 请求头字典。
    User-Agent 从真实用户代理列表中随机选择。
    X-Forwarded-For 和 X-Real-IP 使用随机生成的公共 IP。
    返回：包含 HTTP 头的字典。
    """
    base_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.google.com',
        'Connection': 'keep-alive',
    }

    # 生成 User-Agent，包含错误处理
    try:
        ua = UserAgent()
        user_agent = ua.random
    except Exception as e:
        print(f"警告：无法生成随机 User-Agent，错误：{e}。使用默认值。")
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

    # 生成公共 IP
    while True:
        ip_int = random.randint(1, 0xffffffff)
        ip = socket.inet_ntoa(struct.pack('>I', ip_int))
        if not is_private_ip(ip):
            break

    # 创建请求头字典
    headers = base_headers.copy()
    headers['User-Agent'] = user_agent
    headers['X-Forwarded-For'] = ip
    headers['X-Real-IP'] = ip

    return headers


if __name__ == "__main__":
    # 首次运行可能需要下载用户代理数据
    print(get_ua())