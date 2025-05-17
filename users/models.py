from django.db import models
from django.contrib.auth.models import User # 引用django内置的User模型,通过一对一关系为默认的User拓展用户数据
# Create your models here.
class UserProfile(models.Model):
    owner = models.OneToOneField(User,on_delete=models.CASCADE,verbose_name = '用户')
    User_GENDER_TYPE = (
        ('male','男'),
        ('female','女'),
    )
    nike_name = models.CharField(max_length=20,verbose_name='昵称',blank=True,default='')
    birthday = models.DateField(verbose_name='生日',null=True,blank=True)
    gender = models.CharField(max_length=6,choices=User_GENDER_TYPE,default='male',verbose_name='性别')
    address = models.CharField(max_length=100,verbose_name='地址',blank=True,default='')
    mobile = models.CharField(max_length=11,verbose_name='手机号',blank=True,default='')
    personl_profile = models.CharField(max_length=200,verbose_name='个人简介',blank=True,default='')
    personalized_signature = models.CharField(max_length=100,verbose_name='个性签名',blank=True,default='')
    image = models.ImageField(upload_to='images/%Y/%m',default='images/highLightTitle.png',max_length=100,verbose_name='用户头像')# upload_to指定图片上传的位置
    class Meta:
        verbose_name = '用户详细信息'
        verbose_name_plural = verbose_name
    def __str__(self):
        return self.owner.username
class EmailVerifyRecord(models.Model):

    code = models.CharField(max_length=20,verbose_name='验证码')
    email = models.EmailField(max_length=50,verbose_name='邮箱')
    send_type = models.CharField(max_length=50,choices=(('register','注册'),('forget','找回密码'),('update_email','修改邮箱')),verbose_name='验证码类型')
    send_time = models.DateTimeField(auto_now_add=True,verbose_name='发送时间')
    class Meta:
        verbose_name = '邮箱验证码'
        verbose_name_plural = verbose_name
    def __str__(self):
        return '{0}({1})'.format(self.code,self.email)