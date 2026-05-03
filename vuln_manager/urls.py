from django.views.decorators.csrf import csrf_exempt
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .extensions import wazuh, agent

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path(
        "api/inventory/update/", agent.update_inventory_api, name="api_update_inventory"
    ),
    path("login/", views.login_view, name="login"),
    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="registration/password_reset_form.html",
            email_template_name="registration/password_reset_email.txt",
            subject_template_name="registration/password_reset_subject.txt",
            success_url="/password-reset/done/",
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="registration/password_reset_done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="registration/password_reset_confirm.html",
            success_url="/reset/done/",
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="registration/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
    path("register/", views.register_view, name="register"),
    path("logout/", views.logout_view, name="logout"),
    path("hosts/", views.host_list, name="host_list"),
    path("hosts/add/", views.host_form, name="host_add"),
    path("hosts/<int:pk>/edit/", views.host_form, name="host_edit"),
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
        views.update_vuln_status,
        name="api_update_vuln_status",
    ),
    path("board/", views.kanban_board, name="kanban_board"),
    path("vulnerabilities/add/", views.vuln_add, name="vuln_add"),
    path("import/", views.scan_import, name="scan_import"),
    path("scans/", views.scan_list, name="scan_list"),
    path("scans/<int:pk>/diff/", views.scan_diff, name="scan_diff"),
    path("scans/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
    path("software/", views.software_list, name="software_list"),
    path("software/add/", views.software_form, name="software_add"),
    path("software/<int:pk>/edit/", views.software_form, name="software_edit"),
    path("software/<int:pk>/", views.software_detail, name="software_detail"),
    path(
        "software/<int:pk>/rescan-osv/",
        views.software_rescan_osv,
        name="software_rescan_osv",
    ),
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
    path("ai/dashboard/", views.ki_dashboard, name="ai_dashboard"),
    path("ai/triage", views.do_triage, name="do_triage"),
    path(
        "vulnerabilities/<int:pk>/triage/",
        views.triage_single_vulnerability,
        name="triage_single_vulnerability",
    ),
    path("modules/", views.extensions_view, name="extensions"),
    path(
        "modules/toggle/<str:name_id>/", views.toggle_extension, name="toggle_extension"
    ),
    path("modules/wrike/config/", views.save_wrike_config, name="save_wrike_config"),
    path(
        "modules/email-reporting/config/",
        views.save_email_reporting_config,
        name="save_email_reporting_config",
    ),
    path(
        "modules/email-reporting/send/",
        views.send_email_report_now,
        name="send_email_report_now",
    ),
    path("users/", views.user_admin, name="user_admin"),
    path("users/<int:pk>/staff/", views.set_user_staff, name="set_user_staff"),
    path("users/<int:pk>/delete/", views.delete_user, name="delete_user"),
    path("users/register/toggle/", views.toggle_register, name="toggle_register"),
    path(
        "vulnerabilities/<int:pk>/wrike/create/",
        views.create_wrike_ticket,
        name="create_wrike_ticket",
    ),
    path(
        "vulnerabilities/<int:pk>/wrike/sync/",
        views.sync_wrike_ticket,
        name="sync_wrike_ticket",
    ),
    path("api/webhooks/wazuh/", wazuh.webhook, name="wazuh_webhook"),
    path("dashboard/export/", views.export_dashboard_pdf, name="export_dashboard_pdf"),
]
