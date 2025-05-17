"""
WSGI config for LPTS project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os
import sys

from django.core.wsgi import get_wsgi_application
# 添加项目根目录到PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), '../dirscan/dirsearch'))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "LPTS.settings")

application = get_wsgi_application()
