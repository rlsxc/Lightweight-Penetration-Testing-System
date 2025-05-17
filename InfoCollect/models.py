from django.db import models

# Create your models here.
# class PortList(models.Model):
#     '''端口列表'''
#     num = models.BigIntegerField(verbose_name='端口号')
#     service = models.TextField(max_length=100,verbose_name='服务')
#     protocol = models.CharField(max_length=20,verbose_name='协议',blank=True,default='未知')
#     status = models.CharField(max_length=10,verbose_name='状态',blank=True,default='未知')
#     class Meta:
#         verbose_name=verbose_name_plural='端口列表'