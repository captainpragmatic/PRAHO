from django.urls import path

from . import source_views, views

app_name = "security"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("sources/new/", source_views.source_edit, name="source-enroll"),
    path("sources/<uuid:source_id>/", source_views.source_edit, name="source-edit"),
    path("sources/<uuid:source_id>/retire/", source_views.source_retire, name="source-retire"),
]
