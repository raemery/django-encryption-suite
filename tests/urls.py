"""URLconf for the test suite — exists so the admin's reverse() calls resolve."""

from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),
]
