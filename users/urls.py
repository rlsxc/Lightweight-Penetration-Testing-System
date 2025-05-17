# -*- coding: utf-8 -*-

from django.urls import path
from . import views

app_name = 'users'
urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('active/<str:active_code>/', views.active_user, name='active_user'),
    path('forget_pwd/', views.forget_pwd, name='forget_pwd'),
    path('reset/<str:reset_code>/', views.reset_pwd, name='reset_pwd'),
    path('user_info/', views.user_info, name='user_info'),
    path('logout/', views.logout_view, name='logout'),
    path('edit_user_info/', views.edit_user_info, name='edit_user_info'),
]
