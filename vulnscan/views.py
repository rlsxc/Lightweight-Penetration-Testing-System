from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt
import json, re
from bs4 import BeautifulSoup  # pip install beautifulsoup4
from urllib.parse import urlparse
from vulnscan.models import Middleware_vuln

import time





@csrf_exempt
@login_required(login_url='users:login')
def Middleware_scan(request):
    global Time
    try:
        url = request.POST.get('ip')
        CVE_id = request.POST.get('CVE_id').replace('-', "_")
        Time = time.time()  # time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))时间戳转日期格式
        if insert_Middleware_data(url, CVE_id, Time):
            return success()
    except:
        return error()


@csrf_exempt
@login_required(login_url='users:login')
def start_Middleware_scan(request):
    try:
        url = request.POST.get('ip')
        ip, port = urlparse(url).netloc.split(':')
        CVE_id = request.POST.get('CVE_id').replace('-', "_")
        time.sleep(5)  # 等待数据插入成功后在查询出来扫描
        msg = Middleware_vuln.objects.filter(url=url, status='runing', CVE_id=CVE_id, time=Time)
        print(msg)
        for target in msg:
            result = POC_Check(target.url, target.CVE_id)
            # print("result:", result)
            update_Middleware_data(target.url, target.CVE_id, Time, result)
        return success()
    except:
        return error()


def insert_Middleware_data(url, CVE_id, Time, result=None, status="runing"):
    try:
        Middleware_vuln.objects.create(url=url, status=status, result=result, CVE_id=CVE_id, time=Time)
        print("insert success")
        return True
    except:
        print("data insert error")
        return False


def update_Middleware_data(url, CVE_id, Time, result):
    try:
        Middleware_vuln.objects.filter(url=url, status='runing', CVE_id=CVE_id, time=Time).update(status="completed",
                                                                                                  result=result)
        print("update success")
    except:
        print("data updata error")


def POC_Check(url, CVE_id):
    ip, port = urlparse(url).netloc.split(':')
    # Weblogic

    if CVE_id == "cve_2024_21181":
        from vulnscan.POC.weblogic import cve_2024_21181_poc
        result = cve_2024_21181_poc.poc(ip, int(port), 0)
    elif CVE_id == "cve_2024_21183":
        from vulnscan.POC.weblogic import cve_2024_21183_poc
        result = cve_2024_21183_poc.poc(url, "weblogic")
    # Drupal
    elif CVE_id == "cve_2025_3914":
        from vulnscan.POC.Drupal import cve_2025_3914_poc
        result = cve_2025_3914_poc.poc(url)
    elif CVE_id == "cve_2024_13258":
        from vulnscan.POC.Drupal import cve_2024_13258_poc
        result = cve_2024_13258_poc.poc(url)
    # Tomcat
    elif CVE_id == "cve_2025_31651":
        from vulnscan.POC.tomcat import cve_2025_31651_poc
        result = cve_2025_31651_poc.poc(url)
    # jboss
    elif CVE_id == "cve_2025_2251":
        from vulnscan.POC.jboss import cve_2025_2251_poc
        result = cve_2025_2251_poc.poc(url)
    # nexus
    elif CVE_id == "cve_2025_22513":
        from vulnscan.POC.nexus import cve_2025_22513_poc
        result = cve_2025_22513_poc.poc(ip, port, "admin")
    # Struts2
    elif CVE_id == "cve_2020_17530":
        from vulnscan.POC.struts2 import cve_2020_17530_poc
        result = cve_2020_17530_poc.poc(url)
    return result


def success(code=200, data=[], msg='success'):
    """
    返回成功的json数据
    :param code:
    :param data:
    :param msg:
    :return:
    """
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')


def error(code=400, data=[], msg='error'):
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')
