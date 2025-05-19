'''
网站信息获取模块
环境配置：
1.安装chardet包,beautifulsoup4包
2.更改user-agent
'''
import requests
import chardet
from bs4 import BeautifulSoup
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
'''
传入一个域名
现获取网站的网页名称、所使用的服务器、以及安全规则三项信息
'''
def InformaitonPortionSearch(url):
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
    }

    try:
        res = requests.get(url, headers=headers, timeout=4)#构造请求
        codetype = chardet.detect(res.content).get('encoding')
        res.encoding = codetype

        # title 通过返回体分析——从soup中提取网站的title
        soup = BeautifulSoup(res.text, "html.parser")#构造soup
        title = soup.title.string if soup.title else 'None'
        print('title:', title)

        header = res.headers
        # server 通过返回头分析——从header中获取server
        Server = header.get('Server')
        print('Server:', Server)

        # security 通过返回头分析——从header中获取security信息
        # 思路：输出返回头，提取头部中Server中的信息
        security = []
        if header.get('Content-Security-Policy'):
            security.append('Content-Security-Policy')
        if header.get('X-Webkit-CSP'):
            security.append('X-Webkit-CSP')
        if header.get('X-XSS-Protection'):
            security.append('X-XSS-Protection')
        if header.get('Strict-Transport-Security'):
            security.append('Strict-Transport-Security')
        info = [title,Server,security]
        return info
    except Exception as e:
        print(e)
'''
传入域名或者ip
ip-api.com查询，即实现功能为IP查询
'''
def get_domain_info(domain):
    # ip-api.com 的查询 URL
    url = f"http://ip-api.com/json/{domain}"

    try:
        # 发送 HTTP GET 请求
        response = requests.get(url)
        # 如果请求成功
        if response.status_code == 200:
            # 解析 JSON 响应
            data = response.json()
            return data
            # # 打印获取到的信息
            # print("查询结果:")
            # print(f"域名: {domain}")
            # print(f"国家: {data['country']}")
            # print(f"地区: {data['regionName']}")
            # print(f"城市: {data['city']}")
            # print(f"ISP: {data['isp']}")
        else:
            return response.status_code
            # print("查询失败，HTTP 状态码:", response.status_code)
    except Exception as e:
        print("发生异常:", e)
'''
获取网站权重
实现利用python代码调aizhan.com API获取百度PC权重，移动权重，预计来路等信息。
爱站百度-网站权重”API文档：https://www.aizhan.com/apistore/detail_23/
'''
def webweight(domain):
    api_url = "https://apistore.aizhan.com/baidurank/siteinfos/[06394802f73d32e06a39f29c6da51f35]?domains="

    res = requests.get(api_url + domain, timeout=4,verify=False)
    res_json = json.loads(res.text)

    result = {
        'PC权重': res_json["data"]["success"][0]["pc_br"],
        '移动权重': res_json["data"]["success"][0]["m_br"],
        '预计来路': res_json["data"]["success"][0]["ip"],
        'PC预估流量': res_json["data"]["success"][0]["pc_ip"],
        '移动预估流量': res_json["data"]["success"][0]["m_ip"],
    }
    return result

'''

旁站扫描
'''

header = {
    'Host': 'api.website.cc',
    'Origin': 'http://website.cc',
    'Pragma': 'no-cache',
    'Referer': 'http://website.cc/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132'
}
def side_scan(ip):
    """
    获取旁站信息
    :param ip:
    :return:
    """
    ip = 'www.'+ip
    api_url = 'http://api.webscan.cc/?action=query&ip={}'.format(ip)
    try:
        html = requests.get(api_url, headers=header, timeout=8)
        text = html.text
        # 去掉text首部的BOM字符
        if text.startswith(u'\ufeff'):
            text = text.encode('utf8')[3:].decode('utf8')
        # 检查返回内容是否为空
        if text.find('null') > -1:
            return False
        else:
            return json.loads(text)
    except Exception as e:
        pass  # 空语句
    return False
def get_locating(ip):
    """
    获取ip归属地
    """
    api_url = 'http://ip-api.com/json/{}?lang=zh-CN'.format(ip)
    try:
        res = requests.get(api_url, timeout=4)
        json_data = res.json()
        # result_str = (result[0])
        # print(result)
        result_str = '国家({})，省份({})，城市({})'.format(json_data['country'],json_data['regionName'],json_data['city'])
    except Exception as e:
        result_str = '获取数据失败，请稍后再试'
        print(result_str)
    return result_str