from django.utils import timezone
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import UserAccount, Device, UserDevice


# ----------------------
# Inline para UserAccount
# ----------------------
class UserDeviceInline(admin.TabularInline):
    model = UserDevice
    fk_name = "user"
    extra = 0

    fields = ('device', 'authorized', 'authorized_at', 'authorized_by_display', 'last_login', 'last_ip')
    readonly_fields = ('authorized_at', 'authorized_by_display', 'last_login', 'last_ip')

    def authorized_by_display(self, obj):
        if obj.authorized_by:
            return f"{obj.authorized_by.username} ({obj.authorized_by.email})"
        return "-"
    authorized_by_display.short_description = "Autorizado por"



# ----------------------
# Admin de UserAccount
# ----------------------
class UserAccountAdmin(UserAdmin):
    inlines = [UserDeviceInline]

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
    list_filter = ('is_active', 'is_staff', 'code', 'is_superuser', 'created_at')
    fieldsets = (
        (None, {'fields': ('email', 'code', 'username', 'password', 'verified', 'role')}),
        ('Información Personal', {'fields': ('first_name', 'last_name')}),
        ('Permisos', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Fechas Importantes', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'username', 'first_name', 'last_name', 'role', 'verified',
                'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'
            ),
        }),
    )
    search_fields = ('email', 'code', 'username', 'first_name', 'last_name')
    ordering = ('email',)
    readonly_fields = ('created_at', 'updated_at')
    list_editable = ('role', 'verified',)

    def save_formset(self, request, form, formset, change):
        instances = formset.save(commit=False)
        for obj in instances:
            if isinstance(obj, UserDevice):
                # detectar cambios en authorized
                if obj.pk:
                    old_obj = UserDevice.objects.get(pk=obj.pk)
                    if old_obj.authorized != obj.authorized:
                        obj.authorized_by = request.user
                        obj.authorized_at = timezone.now()
                else:  # nuevo
                    if obj.authorized:
                        obj.authorized_by = request.user
                        obj.authorized_at = timezone.now()
            obj.save()
        formset.save_m2m()
# ----------------------
# Admin de Device
# ----------------------
@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('device_hash', 'hostname', 'os', 'created_at')
    search_fields = ('device_hash', 'hostname', 'os')


# ----------------------
# Admin separado de UserDevice
# ----------------------
@admin.register(UserDevice)
class UserDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'device', 'authorized', 'authorized_at', 'authorized_by', 'last_login', 'last_ip')
    list_filter = ('authorized',)
    search_fields = ('user__email', 'device__device_hash')
    readonly_fields = ('authorized_at', 'authorized_by', 'last_login', 'last_ip')

    actions = ['authorize_devices', 'deauthorize_devices']

    def authorize_devices(self, request, queryset):
        updated = 0
        for obj in queryset:
            obj.authorized = True
            obj.authorized_at = timezone.now()
            obj.authorized_by = request.user
            obj.save()
            updated += 1
        self.message_user(request, f"{updated} dispositivo(s) autorizado(s).")
    authorize_devices.short_description = "Autorizar dispositivos seleccionados"

    def deauthorize_devices(self, request, queryset):
        updated = 0
        for obj in queryset:
            obj.authorized = False
            obj.authorized_at = timezone.now()
            obj.authorized_by = request.user
            obj.save()
            updated += 1
        self.message_user(request, f"{updated} dispositivo(s) desautorizado(s).")
    deauthorize_devices.short_description = "Desautorizar dispositivos seleccionados"


# ----------------------
# Registro principal
# ----------------------
admin.site.register(UserAccount, UserAccountAdmin)
