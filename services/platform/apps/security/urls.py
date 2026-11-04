from django.urls import path

from . import action_views, source_views, views

app_name = "security"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("sources/new/", source_views.source_edit, name="source-enroll"),
    path("sources/<uuid:source_id>/", source_views.source_edit, name="source-edit"),
    path("sources/<uuid:source_id>/retire/", source_views.source_retire, name="source-retire"),
    path("actions/ban/", action_views.ban_create, name="ban-create"),
    path("actions/", action_views.action_list, name="action-list"),
    path("actions/<uuid:action_id>/", action_views.action_detail, name="action-detail"),
    path("decisions/<uuid:decision_id>/revoke/", action_views.decision_revoke, name="decision-revoke"),
    path("sources/<uuid:source_id>/allowlist/", action_views.allowlist_edit, name="allowlist-edit"),
    path("sources/<uuid:source_id>/coverage/", action_views.coverage_edit, name="coverage-edit"),
    path("sources/<uuid:source_id>/coverage/withdraw/", action_views.coverage_withdraw, name="coverage-withdraw"),
]
