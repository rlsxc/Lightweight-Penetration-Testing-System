from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth import authenticate, login, logout

from utils.send_email import send_register_email
from .forms import *
# 邮箱登录注册
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

from .models import *
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required


# Create your views here.

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            # 验证用户
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('index')
            else:
                error_message = '用户名或密码错误，请重新输入'
                return JsonResponse({'error': error_message},status=400)
    else:
        form = LoginForm()
    return render(request, 'users/login.html', {'form': form})


def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            # 创建用户
            new_user = form.save(commit=False)
            new_user.set_password(form.cleaned_data.get('password'))
            new_user.is_active = False
            new_user.save()
            # 发送邮件
            email = form.cleaned_data['email']
            send_register_email(email, 'register')
            return HttpResponse('注册成功,请点击邮箱的激活链接进行激活')
    else:
        form = RegisterForm()
    return render(request, 'users/register.html', {'form': form})


class MyBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


def active_user(request, active_code):
    all_records = EmailVerifyRecord.objects.filter(code=active_code)
    if all_records:
        for record in all_records:
            email = record.email
            user = User.objects.get(email=email)
            user.is_active = True
            user.save()
    else:
        return HttpResponse('激活失败')
    return redirect('users:login')


def forget_pwd(request):
    if request.method == 'POST':
        form = ForgetPwdForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            send_register_email(email, 'forget')
            return HttpResponse('邮件已发送，请点击邮件里面的链接找回密码')
    else:
        form = ForgetPwdForm()
    return render(request, 'users/forget_pwd.html', {'form': form})


def reset_pwd(request, reset_code):
    if request.method == 'POST':
        form = ResetPwdForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            password_again = form.cleaned_data['password_again']
            if password != password_again:
                return HttpResponse('两次密码不一致')
            all_records = EmailVerifyRecord.objects.filter(code=reset_code)
            if all_records:
                for record in all_records:
                    email = record.email
                    user = User.objects.get(email=email)
                    user.set_password(password)
                    user.save()
                    return HttpResponse('重置成功')
            else:
                return HttpResponse('重置失败')
    else:
        form = ResetPwdForm()
    return render(request, 'users/reset_pwd.html', {'form': form})


@login_required(login_url='users:login')
def user_info(request):
    user = User.objects.get(username=request.user)
    return render(request, 'users/user_info.html', {'user': user})


def logout_view(request):
    logout(request)
    return redirect('users:login')


@login_required(login_url='users:login')   # 登录之后允许访问
def edit_user_info(request):
    """ 编辑用户信息 """
    user = User.objects.get(id=request.user.id)
    if request.method == "POST":
        try:
            userprofile = user.userprofile
            user_profile_form = EditUserInfoForm(request.POST, request.FILES, instance=userprofile)  # 向表单填充默认数据
            if user_profile_form.is_valid():
                user_profile_form.save()
                return redirect('users:user_info')
        except UserProfile.DoesNotExist:   # 这里发生错误说明userprofile无数据
            user_profile_form = EditUserInfoForm(request.POST, request.FILES)  # 空表单，直接获取空表单的数据保存
            if user_profile_form.is_valid():
                new_user_profile = user_profile_form.save(commit=False)# commit=False 先不保存，先把数据放在内存中，然后再重新给指定的字段赋值添加进去，提交保存新的数据
                new_user_profile.owner = request.user
                new_user_profile.save()
                return redirect('users:user_info')
    else:
        try:
            userprofile = user.userprofile
            user_profile_form = EditUserInfoForm(instance=userprofile)
        except UserProfile.DoesNotExist:
            user_profile_form = EditUserInfoForm()  # 显示空表单
    return render(request, 'users/edit_user_info.html', locals())