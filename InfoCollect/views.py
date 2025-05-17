import requests
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import json
from utils.InfoCollect import PortScan, InformationGathering, SubDomainSearch,infoLeak


# Create your views here.
@login_required(login_url='users:login')
def port_scan_index(request):
    return render(request, 'InfoCollect/base.html')


@csrf_exempt
def port_scan(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            # 调用端口扫描函数
            scan_result = PortScan.ScanPort(ip_address).pool()
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


def webweight_index(request):
    '''
    网站权重
    '''
    return render(request, 'InfoCollect/webweight.html')


@csrf_exempt
def webweigt(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            scan_result = InformationGathering.webweight(ip_address)
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


@csrf_exempt
def info_collection_view(request):
    if request.method == 'POST':
        # 假设表单提交的数据是 'param1'
        param1 = request.POST.get('ip_address')
        # 调用你的信息收集函数
        try:
            webweight = InformationGathering.webweight(param1)
            domaininfo = InformationGathering.get_domain_info(param1)
            subdomain = SubDomainSearch.subDominMining(param1)
            side = InformationGathering.side_scan(param1)
            # 将结果以 JSON 格式返回给前端，并进行美化
            data = {
                '网站权重': webweight,
                '域名信息': domaininfo,
                '旁站': side,
                '子域名信息': subdomain
            }
            # 使用json.dumps进行美化
            json_response = JsonResponse(data)
            json_response.content = json.dumps(data, indent=4)
            return json_response
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果是 GET 请求，则渲染一个空表单
        return render(request, 'InfoCollect/info_collection.html')


def domainInfo_index(request):
    return render(request, 'InfoCollect/domainInfo_index.html')


@csrf_exempt
def domainInfo(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            scan_result = InformationGathering.get_domain_info(ip_address)
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


@csrf_exempt
def getsideline(request):
    """
    获取旁站信息
    """
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            scan_result = InformationGathering.side_scan(ip_address)
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


def sideline_index(request):
    '''旁站扫描'''
    return render(request, 'InfoCollect/sideline.html')


def subdomain_index(request):
    return render(request, 'InfoCollect/subdomain_index.html')


@csrf_exempt
def subdomain(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            scan_result = SubDomainSearch.subDominMining(ip_address)
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


def infoleak_index(request):
    return render(request,'InfoCollect/infoLeak.html')


@csrf_exempt
def infoleak(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            scan_result = infoLeak.get_infoleak(ip_address)
            # 将扫描结果传递给模板
            return JsonResponse({'scan_result': scan_result})
        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
def CMS_index(request):
    return render(request,'InfoCollect/CMS.html')
@csrf_exempt
def CMS(request):
    if request.method == 'POST':
        try:
            ip_address = request.POST.get('input')
            # 发送POST请求到https://whatweb.net/whatweb.php
            response = requests.post('https://whatweb.net/whatweb.php', data={'target': ip_address})
            # 检查响应状态码是否为200
            if response.status_code == 200:
                scan_result = response.text
                return JsonResponse({'scan_result': scan_result})
            else:
                return JsonResponse({'error': 'Failed to retrieve scan results'}, status=response.status_code)

        except Exception as e:
            # 处理异常情况
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # 如果不是POST请求，返回空响应或其他内容
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

