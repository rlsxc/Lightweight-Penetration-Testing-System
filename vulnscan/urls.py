from django.urls import path
from django.urls import re_path as url
from . import views
app_name = 'vulnscan'
urlpatterns = [





    path('Middleware_scan', views.Middleware_scan, name='Middleware_scan'),
    path('start_Middleware_scan', views.start_Middleware_scan, name='start_Middleware_scan'),

]






