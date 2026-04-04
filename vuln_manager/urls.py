from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login/", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    path("logout/", views.logout_view, name="logout"),
    path("hosts/", views.host_list, name="host_list"),
    path("ports/", views.port_list, name="port_list"),
    path("hosts/<int:pk>/", views.host_detail, name="host_detail"),
    path("hosts/<int:pk>/delete/", views.delete_host, name="delete_host"),
    path(
        "hosts/<int:pk>/criticality/",
        views.update_host_criticality,
        name="update_host_criticality",
    ),
    path("vulnerabilities/", views.vuln_list, name="vuln_list"),
    path("vulnerabilities/<int:pk>/", views.vuln_detail, name="vuln_detail"),
    path(
        "vulnerabilities/<int:pk>/delete/",
        views.delete_vulnerability,
        name="delete_vulnerability",
    ),
    path(
        "vulnerabilities/<int:pk>/status/",
        views.update_vuln_status,
        name="update_vuln_status",
    ),
    path(
        "api/vulnerabilities/<int:pk>/status/",
        views.api_update_vuln_status,
        name="api_update_vuln_status",
    ),
    path("board/", views.kanban_board, name="kanban_board"),
    path("vulnerabilities/add/", views.vuln_add, name="vuln_add"),
    path("import/", views.scan_import, name="scan_import"),
    path("scans/", views.scan_list, name="scan_list"),
    path("scans/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
    path("software/", views.software_list, name="software_list"),
    path("software/add/", views.software_form, name="software_add"),
    path("software/<int:pk>/edit/", views.software_form, name="software_edit"),
    path("software/<int:pk>/", views.software_detail, name="software_detail"),
    path("software/<int:pk>/delete/", views.delete_software, name="delete_software"),
    path(
        "software/<int:pk>/criticality/",
        views.update_software_criticality,
        name="update_software_criticality",
    ),
    path(
        "software/<int:software_pk>/remove-host/<int:host_pk>/",
        views.remove_host_from_software,
        name="remove_host_from_software",
    ),
]
