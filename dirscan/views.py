from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
import os
import json


@login_required(login_url='users:login')
def dirresult(request):
    """渲染初始的 HTML 页面"""
    return render(request, "dir-result.html")


@login_required(login_url='users:login')
def fetch_results(request):
    base_file_path = 'dirscan/dirsearch/reports/target.json'  # 请确保这里是你的JSON文件的实际路径

    results = []
    error = None
    scan_complete = False  # 标志位

    try:
        if os.access(base_file_path, os.F_OK):
            with open(base_file_path, 'r') as f:
                if os.path.getsize(base_file_path) > 0:  # 检查文件是否为空
                    data = json.load(f)  # JSON被转换为Python字典
                    results = data.get('results', [])
                    scan_complete = data.get('scan_complete', False)  # 获取扫描完成标志
                else:
                    raise ValueError("请稍等......")
    except (json.JSONDecodeError, ValueError) as e:
        error = f"暂时未扫描到任何目录: {str(e)}"
    except IOError as e:
        if 'Broken pipe' in str(e):
            scan_complete = True
            error = "连接中断，扫描已完成。"
        else:
            error = f"文件读取错误: {str(e)}"

    if not results and not error:
        error = "暂无结果"

    # 准备数据传递给模板
    context = {
        'results': results,
        'error': error,
        'scan_complete': scan_complete,  # 传递标志位
    }

    return JsonResponse(context)
