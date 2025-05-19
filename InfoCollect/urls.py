# -*- coding: utf-8 -*-

from django.urls import path
from .views import (
    port_scan_index, port_scan, info_collection_view, sideline_index, getsideline,
    subdomain_index, subdomain, webweight_index, webweight, domainInfo_index,
    domainInfo, infoleak_index, infoleak, CMS_index, CMS
)

app_name = 'InfoCollect'

urlpatterns = [
    path('port_scan_index/', port_scan_index, name='port_scan_index'),
    path('port_scan/', port_scan, name='port_scan'),
    path('infocomprehensivecollect/', info_collection_view, name='info_col_index'),
    path('sideline_index/', sideline_index, name='sideline_index'),
    path('getsideline/', getsideline, name='getsideline'),
    path('subdomain_index/', subdomain_index, name='subdomain_index'),
    path('subdomain/', subdomain, name='subdomain'),
    path('webweight_index/', webweight_index, name='webweight_index'),
    path('webweight/', webweight, name='webweight'),  # 修正拼写错误
    path('domainInfo_index/', domainInfo_index, name='domainInfo_index'),
    path('domainInfo/', domainInfo, name='domainInfo'),
    path('infoleak_index/', infoleak_index, name='infoleak_index'),
    path('infoleak/', infoleak, name='infoleak'),
    path('CMS_index/', CMS_index, name='CMS_index'),
    path('CMS/', CMS, name='CMS'),
]