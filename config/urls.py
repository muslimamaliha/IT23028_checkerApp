from django.urls import path
from vulnscan import views
urlpatterns = [path("", views.scan_view, name="scan")]
