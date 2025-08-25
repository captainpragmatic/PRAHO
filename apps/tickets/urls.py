# ===============================================================================
# TICKETS APP URLS - SUPPORT SYSTEM
# ===============================================================================

from django.urls import path

from . import views

app_name = 'tickets'

urlpatterns = [
    path('', views.ticket_list, name='list'),
    path('create/', views.ticket_create, name='create'),
    path('<int:pk>/', views.ticket_detail, name='detail'),
    path('<int:pk>/reply/', views.ticket_reply, name='reply'),
    path('<int:pk>/comments/', views.ticket_comments_htmx, name='comments_htmx'),
    path('<int:pk>/close/', views.ticket_close, name='close'),
    path('<int:pk>/reopen/', views.ticket_reopen, name='reopen'),
    path('attachment/<int:attachment_id>/download/', views.download_attachment, name='download_attachment'),
]
