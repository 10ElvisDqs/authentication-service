from django.contrib import admin
from django.contrib.auth.models import Group, Permission
from .models import Aplicacion, GroupAplicacion, UserGroupAplicacion


# ----------------------
# Inlines
# ----------------------
class GroupAplicacionInline(admin.TabularInline):
    model = GroupAplicacion
    extra = 1
    fields = ('group', 'aplicacion')
    show_change_link = True


class UserGroupAplicacionInline(admin.TabularInline):
    model = UserGroupAplicacion
    extra = 1
    fields = ('user',)
    raw_id_fields = ['user']


# ----------------------
# Admin de Aplicacion
# ----------------------
@admin.register(Aplicacion)
class AplicacionAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'slug', 'activa', 'created_at')
    list_filter = ('activa', 'created_at')
    search_fields = ('nombre', 'slug', 'descripcion')
    prepopulated_fields = {'slug': ('nombre',)}
    list_editable = ('activa',)
    readonly_fields = ('created_at',)
    
    fieldsets = (
        ('Información General', {
            'fields': ('nombre', 'slug', 'descripcion', 'activa')
        }),
        ('URLs', {
            'fields': ('url_frontend', 'url_backend')
        }),
        ('Fechas', {
            'fields': ('created_at',)
        }),
    )

    inlines = [GroupAplicacionInline]


# ----------------------
# Admin de GroupAplicacion
# ----------------------
@admin.register(GroupAplicacion)
class GroupAplicacionAdmin(admin.ModelAdmin):
    list_display = ('group', 'aplicacion', 'count_permissions', 'count_users')
    list_filter = ('aplicacion', 'group')
    search_fields = ('group__name', 'aplicacion__nombre', 'aplicacion__slug')
    
    # Esta es la clave: filter_horizontal para el selector de doble lista
    filter_horizontal = ('permissions',)
    
    fieldsets = (
        ('Información General', {
            'fields': ('group', 'aplicacion')
        }),
        ('Permisos', {
            'fields': ('permissions',),
            'description': 'Selecciona los permisos que tendrá este grupo en esta aplicación.'
        }),
    )
    
    inlines = [UserGroupAplicacionInline]

    def count_permissions(self, obj):
        return obj.permissions.count()
    count_permissions.short_description = "Permisos"

    def count_users(self, obj):
        return obj.usergroupaplicacion_set.count()
    count_users.short_description = "Usuarios"
    
    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "permissions":
            kwargs["queryset"] = Permission.objects.select_related('content_type').order_by(
                'content_type__app_label', 
                'content_type__model',
                'codename'
            )
        return super().formfield_for_manytomany(db_field, request, **kwargs)


# ----------------------
# Admin de UserGroupAplicacion
# ----------------------
@admin.register(UserGroupAplicacion)
class UserGroupAplicacionAdmin(admin.ModelAdmin):
    list_display = ('user', 'group_aplicacion', 'get_aplicacion', 'get_group', 'get_user_email')
    list_filter = ('group_aplicacion__aplicacion', 'group_aplicacion__group')
    search_fields = (
        'user__username',
        'user__email',
        'user__first_name',
        'user__last_name',
        'group_aplicacion__group__name',
        'group_aplicacion__aplicacion__nombre'
    )
    raw_id_fields = ['user']

    actions = ['remove_from_group']

    def get_aplicacion(self, obj):
        return obj.group_aplicacion.aplicacion.nombre
    get_aplicacion.short_description = "Aplicación"
    get_aplicacion.admin_order_field = 'group_aplicacion__aplicacion__nombre'

    def get_group(self, obj):
        return obj.group_aplicacion.group.name
    get_group.short_description = "Grupo"
    get_group.admin_order_field = 'group_aplicacion__group__name'

    def get_user_email(self, obj):
        return obj.user.email
    get_user_email.short_description = "Email"
    get_user_email.admin_order_field = 'user__email'

    def remove_from_group(self, request, queryset):
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f"{count} usuario(s) removido(s) del grupo.")
    remove_from_group.short_description = "Remover usuarios seleccionados del grupo"