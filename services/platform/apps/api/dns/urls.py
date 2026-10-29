from django.urls import path

from . import views

app_name = "dns"

urlpatterns = [
    path("zones/", views.zone_list_api, name="zone_list"),
    path("zones/import/", views.zone_import_api, name="zone_import"),
    path("zones/<uuid:zone_id>/", views.zone_detail_api, name="zone_detail"),
    path("zones/<uuid:zone_id>/export/", views.zone_export_api, name="zone_export"),
    path("zones/<uuid:zone_id>/crosscheck/", views.zone_action_api, {"action": "crosscheck"}, name="zone_crosscheck"),
    path("zones/<uuid:zone_id>/confirm/", views.zone_action_api, {"action": "confirm"}, name="zone_confirm"),
    path("zones/<uuid:zone_id>/switch/", views.zone_action_api, {"action": "switch"}, name="zone_switch"),
    path("zones/<uuid:zone_id>/delete/", views.zone_action_api, {"action": "delete"}, name="zone_delete"),
    path("zones/<uuid:zone_id>/records/", views.zone_record_api, name="record_create"),
    path("zones/<uuid:zone_id>/records/<uuid:record_id>/", views.zone_record_api, name="record_update"),
    path("zones/<uuid:zone_id>/records/<uuid:record_id>/detail/", views.zone_record_detail_api, name="record_detail"),
]
