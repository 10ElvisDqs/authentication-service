# apps/aplicaciones/urls.py
from django.urls import path
from .views import SincronizarPermisosView

urlpatterns = [
    path('sincronizar-permisos/', SincronizarPermisosView.as_view()),
]