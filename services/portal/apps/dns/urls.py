from django.urls import path

from . import views

app_name = "dns"

urlpatterns = [
    path("", views.zone_list, name="list"),
    path("import/<int:service_id>/", views.zone_import, name="import"),
    path("zones/<uuid:zone_id>/", views.zone_detail, name="detail"),
    path("zones/<uuid:zone_id>/export/", views.zone_export, name="export"),
    path("zones/<uuid:zone_id>/delete/", views.zone_delete, name="delete"),
    path("zones/<uuid:zone_id>/records/new/", views.zone_record, name="record_create"),
    path("zones/<uuid:zone_id>/records/<uuid:record_id>/", views.zone_record, name="record_edit"),
    path("zones/<uuid:zone_id>/records/<uuid:record_id>/delete/", views.record_delete, name="record_delete"),
    path("zones/<uuid:zone_id>/<str:action>/", views.zone_action, name="action"),
]
