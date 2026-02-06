import uuid
from django.db import models
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.db import models
from django.contrib.auth.models import Permission
from django.utils.text import slugify
from django.contrib.auth import get_user_model

User = get_user_model()

class Aplicacion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nombre = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)

    url_frontend = models.URLField()
    url_backend = models.URLField()

    descripcion = models.TextField(blank=True)
    activa = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.nombre


class GroupAplicacion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    aplicacion = models.ForeignKey(Aplicacion, on_delete=models.CASCADE)
    
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        verbose_name="permisos"
    )

    class Meta:
        unique_together = ("group", "aplicacion")
        verbose_name = "Grupo de Aplicación"
        verbose_name_plural = "Grupos de Aplicación"

    def __str__(self):
        return f"{self.group.name} - {self.aplicacion.slug}"

class UserGroupAplicacion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group_aplicacion = models.ForeignKey(GroupAplicacion, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "group_aplicacion")
        verbose_name = "Usuario en Grupo de Aplicación"
        verbose_name_plural = "Usuarios en Grupos de Aplicación"

    def __str__(self):
        return f"{self.user.username} - {self.group_aplicacion}"
    


class PermissionMeta(models.Model):
    permission = models.OneToOneField(
        Permission,
        on_delete=models.CASCADE,
        related_name="meta"
    )

    slug = models.SlugField(unique=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            base = f"{self.permission.content_type.app_label}-{self.permission.codename}"
            self.slug = slugify(base)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.slug
