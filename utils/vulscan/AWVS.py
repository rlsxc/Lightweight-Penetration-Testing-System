# -*- coding: utf-8 -*-


import json
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
tarurl="https://47.113.144.189:13443/"
api_key="1986ad8c0a5b3df4d7028d5f3c06e936cb7d9f782e7ad4a13b315daf0ea14b216"
headers={"X-Auth":api_key,"Content-type":"application/json;charset=utf8"}
def targets():
    api_url=tarurl+"/api/v1/targets"
    r=requests.get(url=api_url,headers=headers,verify=False)

def post_targets(url):
    api_url = tarurl + "/api/v1/targets"
    data={
        "address": url,
        "description": "last_target",
        "criticality": "10"
    }
    data_json=json.dumps(data)
    r = requests.post(url=api_url, headers=headers, data=data_json,verify=False)
    target_id=r.json().get("target_id")
    return target_id

def scans(target_id):
    api_url = tarurl + "/api/v1/scans"
    data = {
        "target_id": target_id,
        "profile_id": "11111111-1111-1111-1111-111111111112",
        "schedule": {
            "disable": False,
            "start_date": None,
            "time_sensitive": False
        }
    }
    data_json = json.dumps(data)
    r = requests.post(url=api_url, headers=headers, data=data_json, verify=False)

def scan_id():
    api_url = tarurl + "/api/v1/scans"
    r = requests.get(url=api_url, headers=headers, verify=False)
    scan_id=r.json().get("scans")[0].get("scan_id")
    return scan_id

def generate(scan_id):
    api_url = tarurl + "/api/v1/reports"
    data = {
        "template_id": "11111111-1111-1111-1111-111111111115",
        "source": {
            "list_type": "scans",
            "id_list": [scan_id]
        }
    }
    data_json = json.dumps(data)
    r = requests.post(url=api_url, headers=headers, data=data_json, verify=False)

def html():
    api_url = tarurl + "/api/v1/reports"
    r = requests.get(url=api_url, headers=headers, verify=False)
    html = r.json().get("reports")[0].get("download")[0]
    html_url = tarurl+html
    r = requests.get(url=html_url, headers=headers, verify=False)
    with open("report.html","wb") as code:
        code.write(r.content)
        code.close()

def pdf():
    api_url = tarurl + "/api/v1/reports"
    r = requests.get(url=api_url, headers=headers, verify=False)
    pdf = r.json().get("reports")[0].get("download")[1]
    pdf_url = tarurl+pdf
    r = requests.get(url=pdf_url, headers=headers, verify=False)
    with open("report.pdf","wb") as code:
        code.write(r.content)
        code.close()

if __name__ == '__main__':
    targets() #扫描目标，扫描的目标为awvs中target中的
    target_id=post_targets("http://www.cqupt.edu.cn/")#添加目标
    time.sleep(10)
    scans(target_id)
    time.sleep(10)
    scan_target_id=scan_id()
    generate(scan_id)
    time.sleep(10)
    html()