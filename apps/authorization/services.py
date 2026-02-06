# apps/aplicaciones/services.py
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.http import Http404
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
from .models import Aplicacion


def sincronizar_permisos(aplicacion_slug):
    """
    Sincroniza permisos desde un sistema externo usando GraphQL.
    
    Los permisos sincronizados se almacenan en el modelo nativo Permission de Django
    con una convención de nombre: {slug_aplicacion}_{codigo_externo}
    
    Args:
        aplicacion_slug (str): Slug de la aplicación a sincronizar
        
    Returns:
        dict: Resumen de la sincronización con estadísticas
        
    Raises:
        Http404: Si la aplicación no existe o está inactiva
        ValidationError: Si hay errores en la sincronización o consulta GraphQL
    """
    # Verificar que la aplicación existe y está activa
    try:
        aplicacion = Aplicacion.objects.get(slug=aplicacion_slug, activa=True)
    except Aplicacion.DoesNotExist:
        raise Http404(f"Aplicación con slug '{aplicacion_slug}' no encontrada o inactiva")

    try:
        # Configurar cliente GraphQL con timeout y headers apropiados
        transport = RequestsHTTPTransport(
            url=aplicacion.url_backend,
            use_json=True,
            timeout=30,
            headers={
                'Content-Type': 'application/json',
            }
        )
        client = Client(
            transport=transport, 
            fetch_schema_from_transport=False
        )

        # Query GraphQL para obtener permisos del sistema externo
        query = gql("""
            query ListarTodasLosPermisos {
                permisos {
                    codigo
                    nombre
                }
            }
        """)

        # Ejecutar consulta GraphQL
        response = client.execute(query)
        permisos_externos = response.get('permisos', [])

        if not permisos_externos:
            raise ValidationError(
                f'No se encontraron permisos en el sistema externo: {aplicacion.url_backend}'
            )

        # Obtener content_type genérico para los permisos
        # Usamos el ContentType de Aplicacion para mantener consistencia
        content_type = ContentType.objects.get_for_model(Aplicacion)

        # Prefijo para identificar permisos de esta aplicación
        # Formato: {slug}_{codigo} (ej: "sistema-ventas_crear_cliente")
        prefix = f"{aplicacion.slug}_"

        # Obtener todos los permisos actuales de esta aplicación
        permisos_actuales = Permission.objects.filter(
            codename__startswith=prefix
        ).select_related('content_type')

        # Crear mapa de permisos actuales (codigo sin prefijo -> objeto Permission)
        # Esto permite búsquedas O(1) en lugar de O(n)
        permisos_actuales_map = {
            p.codename.replace(prefix, '', 1): p 
            for p in permisos_actuales
        }

        # Set de códigos externos para identificar permisos a eliminar
        codigos_externos = {p['codigo'] for p in permisos_externos}

        # Contadores para el resumen
        creados = 0
        actualizados = 0
        eliminados = 0

        # Procesar permisos externos: crear o actualizar
        for permiso_externo in permisos_externos:
            codigo = permiso_externo['codigo']
            nombre = permiso_externo['nombre']
            codename = f"{prefix}{codigo}"
            
            permiso_existente = permisos_actuales_map.get(codigo)

            if permiso_existente:
                # Actualizar solo si el nombre cambió (evita writes innecesarios)
                if permiso_existente.name != nombre:
                    permiso_existente.name = nombre
                    permiso_existente.save(update_fields=['name'])
                    actualizados += 1
            else:
                # Crear nuevo permiso
                Permission.objects.create(
                    codename=codename,
                    name=nombre,
                    content_type=content_type
                )
                creados += 1

        # Eliminar permisos que ya no existen en el sistema externo
        for codigo, permiso_actual in permisos_actuales_map.items():
            if codigo not in codigos_externos:
                permiso_actual.delete()
                eliminados += 1

        # Contar total de permisos sincronizados
        total = Permission.objects.filter(codename__startswith=prefix).count()

        return {
            "message": f"Sincronización completada para la aplicación {aplicacion.nombre}",
            "aplicacion": {
                "id": str(aplicacion.id),
                "nombre": aplicacion.nombre,
                "slug": aplicacion.slug,
                "url_frontend": aplicacion.url_frontend,
                "url_backend": aplicacion.url_backend
            },
            "resumen": {
                "creados": creados,
                "actualizados": actualizados,
                "eliminados": eliminados,
                "total": total
            }
        }

    except ValidationError:
        # Re-raise ValidationError sin modificar
        raise
    
    except Exception as error:
        # Capturar cualquier otro error (GraphQL, red, etc.)
        raise ValidationError(
            f"Error al sincronizar permisos desde {aplicacion.url_backend}: {str(error)}"
        )