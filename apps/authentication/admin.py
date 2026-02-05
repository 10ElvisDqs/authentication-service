from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import UserAccount, Device, UserDevice


class UserDeviceInline(admin.TabularInline):
    model = UserDevice
    extra = 0
    readonly_fields = (
        'device',
        'authorized_at',
        'last_login',
        'last_ip',
    )
    fields = (
        'device',
        'authorized',
        'authorized_at',
        'last_login',
        'last_ip',
    )
    can_delete = False

class UserAccountAdmin(UserAdmin):

    inlines = [UserDeviceInline]

    # Campos a mostrar en la lista de usuarios
    list_display = (
        'email',
        'username',
        'first_name',
        'last_name',
        'is_active',
        'is_staff',
        'role',
        'verified',
    )
    list_filter = ('is_active', 'is_staff', 'code','is_superuser', 'created_at')

    # Campos a mostrar en el formulario de edición
    fieldsets = (
        (None, {'fields': ('email', 'code', 'username', 'password', 'verified', 'role')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )

    # Campos a mostrar al crear un nuevo usuario
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name','role','verified', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )

    search_fields = ('email', 'code','username', 'first_name', 'last_name')
    ordering = ('email',)
    readonly_fields = ('created_at', 'updated_at')
    list_editable = ('role','verified',)

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('device_hash', 'hostname', 'os', 'created_at')
    search_fields = ('device_hash', 'hostname', 'os')


admin.site.register(UserAccount, UserAccountAdmin)