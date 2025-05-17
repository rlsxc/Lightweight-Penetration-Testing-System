# -*- coding: utf-8 -*-

from django import forms
from django.contrib.auth.models import User
from .models import UserProfile


class LoginForm(forms.Form):
    username = forms.CharField(
        label='Username or Email',
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your username or email'})
    )

    password = forms.CharField(
        label='Password',
        min_length=6,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your password'})
    )


class RegisterForm(forms.ModelForm):
    username = forms.CharField(label='Username', max_length=50,
                               widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your '
                                                                                                     'username'}))
    password = forms.CharField(label='Password', min_length=6,
                               widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your '
                                                                                                         'password'}))
    password_again = forms.CharField(label='Confirm Password', min_length=6, widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': 'Please enter your password again'}))
    email = forms.EmailField(label='Email',
                             widget=forms.EmailInput(
                                 attrs={'class': 'form-control', 'placeholder': 'Enter your email'}))

    class Meta:
        model = User
        fields = ['username', 'password', 'password_again', 'email', ]

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('用户名已存在')
        return username

    def clean_password_again(self):
        if self.cleaned_data['password'] != self.cleaned_data['password_again']:
            raise forms.ValidationError('两次密码不一致')
        return self.cleaned_data['password_again']


class ForgetPwdForm(forms.Form):
    # 忘记密码页表单
    email = forms.EmailField(label='email',
                             widget=forms.EmailInput(
                                 attrs={'class': 'form-control', 'placeholder': 'Enter your registered '
                                                                                'email'}))


class ResetPwdForm(forms.Form):
    # 修改密码表单
    password = forms.CharField(label='Password', min_length=6,
                               widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Please '
                                                                                                         'enter the '
                                                                                                         'password '
                                                                                                         'you want to '
                                                                                                         'modify'}))
    password_again = forms.CharField(label='Confirm password', min_length=6, widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': 'Please enter your password again'}))

    def clean_password_again(self):
        if self.cleaned_data['password'] != self.cleaned_data['password_again']:
            raise forms.ValidationError('两次密码不一致')
        return self.cleaned_data['password_again']


class UserForm(forms.ModelForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'input', 'disabled': 'disabled'
    }))

    class Meta:
        model = User
        fields = ('email',)


class EditUserInfoForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = (
            'mobile', 'nike_name', 'address', 'birthday', 'gender', 'personl_profile', 'personalized_signature',
            'image')
