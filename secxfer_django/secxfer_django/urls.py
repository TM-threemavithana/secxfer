from django.contrib import admin
from django.urls import path
from kdc import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('challenge', views.challenge_view),
    path('register', views.register_view),
    path('keys/<str:key_id>', views.keys_view),
    path('upload', views.upload_view),
    path('inbox/<str:key_id>', views.inbox_view),
    path('download/<int:file_id>', views.download_view),
    path('audit/log', views.audit_log_view),
]
