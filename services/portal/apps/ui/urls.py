"""URL configuration for the ui app — styleguide only."""

from django.urls import path

from . import views

app_name = "ui"

urlpatterns = [
    path("", views.styleguide, name="styleguide"),
]
