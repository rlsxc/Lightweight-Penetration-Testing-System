from django.contrib import admin
from django.contrib.auth.models import User
from .models import UserProfile, EmailVerifyRecord
# Register your models here.

# 我们看到的这个用户选项时官方通过UserAdmin来实现的，我们可以通过继承UserAdmin来自定义用户选项
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# 我们自定义的用户模型,取消官方的注册
admin.site.unregister(User)


# 定义关联对象的样式，StackedInline是纵向排列每一行，TabularInline是横向排列每一行
class UserProfileInline(admin.StackedInline):
    model = UserProfile


# 关联UserProfile
class UserProAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)


# 重新注册User
admin.site.register(User, UserProAdmin)


@admin.register(EmailVerifyRecord)
class EmailVerifyRecordAdmin(admin.ModelAdmin):
    list_display = ('code',)
