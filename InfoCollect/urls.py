# -*- coding: utf-8 -*-

from django.urls import path
from .views import *
app_name = 'InfoCollect'
urlpatterns = [
    path('port_scan_index/', port_scan_index, name='port_scan_index'),
    path('port_scan', port_scan, name='port_scan'),
    path('infocomprehensivecollect/',info_collection_view,name='info_col_index'),
    path('sideline_index/',sideline_index,name='sideline_index'),
    path('getsideline',getsideline,name='getsideline'),
    path('subdomain_index/',subdomain_index,name='subdomain_index'),
    path('subdomain', subdomain, name='subdomain'),
    path('webweight_index/',webweight_index,name='webweight_index'),
    path('webweight',webweigt,name='webweight'),
    path('domainInfo_index/',domainInfo_index,name='domainInfo_index'),
    path('domainInfo',domainInfo,name='domainInfo'),
    path('infoleak_index/',infoleak_index,name='infoleak_index'),
    path('infoleak',infoleak,name='infoleak'),
    path('CMS_index/', CMS_index, name='CMS_index'),
    path('CMS', CMS, name='CMS'),
]