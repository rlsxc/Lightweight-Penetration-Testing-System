# -*- coding: utf-8 -*-

from django.core.mail import send_mail  # 发送邮件
from random import Random
from users.models import EmailVerifyRecord
import string


def random_str(randomlength=8):
    str = ''
    chars = string.ascii_letters + string.digits
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):
        str += chars[random.randint(0, length)]
    return str


def send_register_email(email, send_type='register'):
    email_record = EmailVerifyRecord()
    code = random_str(16)
    email_record.code = code
    email_record.email = email
    email_record.send_type = send_type
    email_record.save()
    email_title = ''
    email_body = ''
    if send_type == 'register':
        email_title = '注册激活链接'
        email_body = '请点击下面的链接激活你的账号: http://127.0.0.1:8080/users/active/{0}'.format(code)
        send_status = send_mail(email_title, email_body, 'htaddd80@qq.com', [email])
        if send_status:
            pass
    elif send_type == 'forget':
        email_title = '密码重置链接'
        email_body = '请点击下面的链接重置你的密码: http://127.0.0.1:8080/users/reset/{0}'.format(code)
        send_status = send_mail(email_title, email_body, 'htaddd80@qq.com', [email])
        if send_status:
            pass
