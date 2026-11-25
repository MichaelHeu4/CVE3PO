import logging
import io
import zipfile
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import ContextAssessment, ContextAgent, ContextJob, Extension, Host, Vulnerability
from .utils.context_assessment import generate_proposal
from context_agent.policy import validate_query

logger = logging.getLogger(__name__)


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def sync_wazuh_inventory(request):
    from .utils.wazuh_sync import start_sync
    if not Extension.objects.filter(name_id="wazuh", is_active=True).exists():
        messages.error(request, "Enable the Wazuh module first.")
    elif start_sync():
        messages.success(request, "Wazuh inventory sync started in the background.")
    else:
        messages.warning(request, "A Wazuh inventory sync is already running.")
    return redirect("extensions")


@login_required
@user_passes_test(lambda user: user.is_staff)
def download_context_agent(request):
    """Dedicated pilot package; never changes the legacy agent artifacts."""
    directory = settings.BASE_DIR / "context_agent"
    files = ("agent.py", "apache_check.py", "policy.py", "windows_service.py", "cve3po-context-agent.service", "config.example.json", "README.md")
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(directory / name, arcname="cve3po-context-agent/" + name)
    response = HttpResponse(archive_data.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = 'attachment; filename="cve3po-context-agent-pilot.zip"'
    return response


def _target(vulnerability, host_id):
    if not str(host_id or "").isdigit():
        return None
    host = Host.objects.filter(pk=host_id).first()
    if host is None:
        return None
    allowed = (vulnerability.host_id == host.pk if vulnerability.host_id else
               bool(vulnerability.software_id and vulnerability.software.hosts.filter(pk=host.pk).exists()))
    return host if allowed else None


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def prepare_context(request, pk):
    vulnerability = get_object_or_404(Vulnerability.objects.select_related("host", "software"), pk=pk)
    host = _target(vulnerability, request.POST.get("host_id"))
    if host is None:
        messages.error(request, "The selected host is not a target of this finding.")
        return redirect("vuln_detail", pk=pk)
    try:
        sources, proposal, provider, model = generate_proposal(vulnerability, host)
        ContextAssessment.objects.create(vulnerability=vulnerability, host=host, created_by=request.user,
                                         sources=sources, proposal=proposal, provider=provider, model_name=model)
    except Exception:
        logger.exception("Could not generate context proposal for finding %s", pk)
        messages.error(request, "Context proposal failed. Check AI configuration and server logs.")
    else:
        messages.success(request, "Context proposal created for review; no query has been executed.")
    return redirect("vuln_detail", pk=pk)


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def approve_context(request, pk, assessment_id):
    assessment = get_object_or_404(ContextAssessment.objects.select_related("vulnerability", "host"), pk=assessment_id, vulnerability_id=pk)
    if _target(assessment.vulnerability, assessment.host_id) is None:
        messages.error(request, "Host is no longer a target of this finding.")
        return redirect("vuln_detail", pk=pk)
    agent = ContextAgent.objects.filter(host=assessment.host, enabled=True).first()
    if not agent:
        messages.error(request, "No enabled context agent is registered for this host.")
        return redirect("vuln_detail", pk=pk)
    try:
        query = validate_query(assessment.proposal.get("query", ""))
    except ValueError as exc:
        messages.error(request, f"Query cannot be approved: {exc}")
        return redirect("vuln_detail", pk=pk)
    ContextJob.objects.create(agent=agent, assessment=assessment, kind="query", query=query,
                              approved_by=request.user, expires_at=timezone.now()+timedelta(hours=1),
                              target_software=str(assessment.vulnerability.software or "")[:500],
                              target_os=assessment.host.operating_system or "")
    messages.success(request, "Query approved for this agent and queued for one hour.")
    return redirect("vuln_detail", pk=pk)


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def approve_apache_context(request, pk, assessment_id):
    assessment = get_object_or_404(ContextAssessment.objects.select_related("vulnerability", "host"), pk=assessment_id, vulnerability_id=pk)
    vuln = assessment.vulnerability
    agent = ContextAgent.objects.filter(host=assessment.host, enabled=True).first()
    if _target(vuln, assessment.host_id) is None or not agent:
        messages.error(request, "This check requires a matching target host and an enabled context agent.")
    elif not agent.capabilities.get("apache_check"):
        messages.error(request, "The context agent must be updated and configured for Apache first.")
    else:
        ContextJob.objects.create(agent=agent, assessment=assessment, kind="apache", approved_by=request.user,
                                  expires_at=timezone.now()+timedelta(hours=1),
                                  target_software=str(vuln.software or "")[:500], target_os=assessment.host.operating_system or "")
        messages.success(request, "Apache configuration evidence collection queued for this host.")
    return redirect("vuln_detail", pk=pk)


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def review_context(request, pk, job_id):
    job = get_object_or_404(ContextJob.objects.select_related("assessment"), pk=job_id, assessment__vulnerability_id=pk, kind__in=["query", "apache"])
    verdict = request.POST.get("verdict")
    notes = request.POST.get("notes", "").strip()
    if job.status != "completed" or job.is_stale or verdict not in ("met", "not_met", "not_determined") or not notes or len(notes) > 5000:
        messages.error(request, "Review requires a recent successful result, a valid verdict and reasoning.")
    else:
        job.verdict, job.review_notes, job.reviewed_by, job.reviewed_at = verdict, notes, request.user, timezone.now()
        job.save(update_fields=["verdict", "review_notes", "reviewed_by", "reviewed_at"])
        messages.success(request, "Review saved. Finding status and SSVC are unchanged.")
    return redirect("vuln_detail", pk=pk)
