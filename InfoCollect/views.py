import re
import requests
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.core.exceptions import ValidationError
from utils.InfoCollect import PortScan, InformationGathering, SubDomainSearch, infoLeak

# Create your views here.
@login_required(login_url='users:login')
def port_scan_index(request):
    return render(request, 'InfoCollect/base.html')

def validate_input(ip_address):
    """验证输入的 IP 或域名格式"""
    if not ip_address:
        raise ValidationError("输入不能为空")
    # 移除协议和路径
    ip_address = ip_address.replace('http://', '').replace('https://', '').rstrip('/')
    ip_address = re.sub(r'/\w+', '', ip_address)
    if ':' in ip_address:
        ip_address = re.sub(r':\d+', '', ip_address)
    # 验证 IP 或域名格式
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not (re.match(ip_pattern, ip_address) or re.match(domain_pattern, ip_address)):
        raise ValidationError("无效的 IP 或域名格式")
    return ip_address

def port_scan(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            # 调用端口扫描函数，指定常用端口
            scan_result = PortScan.ScanPort(ip_address, ports=[22, 80, 443, 3306, 3389]).pool()
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"扫描失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@login_required(login_url='users:login')
def webweight_index(request):
    """网站权重"""
    return render(request, 'InfoCollect/webweight.html')

def webweight(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            scan_result = InformationGathering.webweight(ip_address)
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"网站权重查询失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@login_required(login_url='users:login')
def info_collection_view(request):
    if request.method == 'POST':
        try:
            param1 = request.POST.get('ip_address')
            param1 = validate_input(param1)
            webweight = InformationGathering.webweight(param1)
            domaininfo = InformationGathering.get_domain_info(param1)
            subdomain = SubDomainSearch.subDominMining(param1)
            side = InformationGathering.side_scan(param1)
            data = {
                '网站权重': webweight,
                '域名信息': domaininfo,
                '旁站': side,
                '子域名信息': subdomain
            }
            return JsonResponse(data, json_dumps_params={'indent': 4})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"信息收集失败：{str(e)}"}, status=500)
    else:
        return render(request, 'InfoCollect/info_collection.html')

@login_required(login_url='users:login')
def domainInfo_index(request):
    return render(request, 'InfoCollect/domainInfo_index.html')

def domainInfo(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            scan_result = InformationGathering.get_domain_info(ip_address)
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"域名信息查询失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

def getsideline(request):
    """获取旁站信息"""
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            scan_result = InformationGathering.side_scan(ip_address)
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"旁站扫描失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@login_required(login_url='users:login')
def sideline_index(request):
    """旁站扫描"""
    return render(request, 'InfoCollect/sideline.html')

@login_required(login_url='users:login')
def subdomain_index(request):
    return render(request, 'InfoCollect/subdomain_index.html')

def subdomain(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            scan_result = SubDomainSearch.subDominMining(ip_address)
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"子域名挖掘失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@login_required(login_url='users:login')
def infoleak_index(request):
    return render(request, 'InfoCollect/infoLeak.html')

def infoleak(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            ip_address = validate_input(ip_address)
            scan_result = infoLeak.get_infoleak(ip_address)
            return JsonResponse({'scan_result': scan_result})
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"信息泄露检测失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@login_required(login_url='users:login')
def CMS_index(request):
    return render(request, 'InfoCollect/CMS.html')


def CMS(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            print(f"Input received: {ip_address}")
            ip_address = validate_input(ip_address)
            print(f"Validated input: {ip_address}")
            if not ip_address.startswith(('http://', 'https://')):
                ip_address = f'http://{ip_address}'
            print(f"Sending request to whatcms.org with target: {ip_address}")

            api_key = "w27f6ho0q0x69qrcig08tb4klczp5rqu46w9y4v6fq4bcjrtqj5c2jqd56llglvd9u750e"
            response = requests.get(
                f"https://whatcms.org/API/CMS?key={api_key}&url={ip_address}",
                timeout=10
            )
            print(f"Response status code: {response.status_code}")
            response.raise_for_status()

            result = response.json()
            print(f"API response: {result}")
            print(f"Success field: {result.get('success', False)}")  # 调试：打印 success 字段
            if 'result' in result:  # 简化条件，只检查 result 字段
                if result['result'].get('code') == 120:  # Rate Limited
                    retry_seconds = result['result'].get('retry_in_seconds', 0)
                    return JsonResponse({'error': f"API 速率限制，请在 {retry_seconds} 秒后重试"}, status=429)
                scan_result = result['result'].get('name', 'Unknown CMS')
                print(f"Extracted name: {scan_result}")
            else:
                scan_result = 'Unknown CMS'
            print(f"Response content: {scan_result}")
            return JsonResponse({'scan_result': scan_result})
        except requests.exceptions.Timeout:
            print("Timeout occurred")
            return JsonResponse({'error': '请求超时，请稍后重试'}, status=504)
        except requests.exceptions.RequestException as e:
            print(f"Request error: {str(e)}")
            return JsonResponse({'error': f"CMS 识别失败：{str(e)}"}, status=500)
        except ValidationError as e:
            print(f"Validation error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': f"CMS 识别失败：{str(e)}"}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

