"""
URL patterns for audit app.
"""

from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('log/', views.audit_log, name='log'),
    path('export/', views.export_data, name='export'),
]
