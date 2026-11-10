"""URLconf for the simpleteams middleware tests: one view that reports the current silo."""

from django.http import HttpResponse
from django.urls import path

from encryption_suite.adapters.silos.context import get_current_silo


def current_silo(request):
    silo = get_current_silo()
    return HttpResponse("" if silo is None else str(silo.pk))


urlpatterns = [
    path("silo/", current_silo),
]
