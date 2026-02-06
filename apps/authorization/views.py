# apps/aplicaciones/views.py
from rest_framework import permissions
from rest_framework_api.views import StandardAPIView
from core.permissions import HasValidAPIKey
from .services import sincronizar_permisos
from django.http import Http404
from django.core.exceptions import ValidationError


class SincronizarPermisosView(StandardAPIView):
    """
    Vista para sincronizar permisos de una aplicación desde su sistema externo.
    
    POST /api/aplicaciones/sincronizar-permisos/
    Body:
    {
        "aplicacion_slug": "nombre-app"
    }
    
    Response:
    {
        "message": "Sincronización completada para la aplicación [nombre]",
        "aplicacion": {
            "id": "uuid",
            "nombre": "string",
            "slug": "string",
            "url_frontend": "url",
            "url_backend": "url"
        },
        "resumen": {
            "creados": int,
            "actualizados": int,
            "eliminados": int,
            "total": int
        }
    }
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        aplicacion_slug = request.data.get('aplicacion_slug')
        
        if not aplicacion_slug:
            return self.error("El campo 'aplicacion_slug' es requerido")
        
        try:
            resultado = sincronizar_permisos(aplicacion_slug)
            return self.response(resultado)
            
        except Http404 as e:
            return self.error(str(e), status=404)
            
        except ValidationError as e:
            return self.error(str(e), status=400)
            
        except Exception as e:
            return self.error(
                f"Error inesperado al sincronizar permisos: {str(e)}", 
                status=500
            )