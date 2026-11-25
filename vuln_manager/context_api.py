"""Per-installation authenticated context agent protocol."""
import hashlib
import json
import secrets
from datetime import timedelta

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import ContextAgent, ContextJob
from context_agent.policy import validate_query


def _agent(request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or len(auth) > 256:
        return None
    digest = hashlib.sha256(auth[7:].encode()).hexdigest()
    return ContextAgent.objects.filter(token_hash=digest, enabled=True).first()


def _body(request):
    if len(request.body) > 2_000_000:
        raise ValueError("Request too large")
    value = json.loads(request.body or b"{}")
    if not isinstance(value, dict):
        raise ValueError("Invalid request")
    return value


@csrf_exempt
@require_POST
def poll(request):
    agent = _agent(request)
    if agent is None:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        body = _body(request)
        capabilities = body.get("capabilities", {})
        if not isinstance(capabilities, dict) or len(json.dumps(capabilities)) > 4096:
            raise ValueError("Invalid capabilities")
    except (ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "invalid request"}, status=400)
    now = timezone.now()
    with transaction.atomic():
        agent = ContextAgent.objects.select_for_update().get(pk=agent.pk)
        agent.last_seen = now
        agent.capabilities = capabilities
        if agent.last_inventory_requested is None or agent.last_inventory_requested <= now - timedelta(hours=1):
            ContextJob.objects.create(agent=agent, kind="inventory", expires_at=now + timedelta(hours=1))
            agent.last_inventory_requested = now
        agent.save(update_fields=["last_seen", "capabilities", "last_inventory_requested"])
        ContextJob.objects.filter(agent=agent, status__in=["pending", "claimed"], expires_at__lte=now).update(status="expired")
        # Expired leases can be retried; old lease tokens cannot submit results.
        ContextJob.objects.filter(agent=agent, status="claimed", claimed_at__lt=now-timedelta(minutes=5)).update(status="pending", lease_hash="")
        job = ContextJob.objects.filter(agent=agent, status="pending", expires_at__gt=now).order_by("created_at", "id").first()
        if not job:
            return JsonResponse({"job": None})
        if job.kind == "query":
            try:
                validate_query(job.query)
            except ValueError:
                job.status = "failed"
                job.result = {"error": "Query no longer allowed"}
                job.save(update_fields=["status", "result"])
                return JsonResponse({"job": None})
        lease = secrets.token_urlsafe(32)
        # Conditional update is essential on SQLite, where select_for_update is a no-op.
        claimed = ContextJob.objects.filter(pk=job.pk, status="pending").update(status="claimed", claimed_at=now, lease_hash=hashlib.sha256(lease.encode()).hexdigest())
        if not claimed:
            return JsonResponse({"job": None})
    return JsonResponse({"job": {"id": job.pk, "kind": job.kind, "query": job.query, "lease": lease, "expires_at": job.expires_at.isoformat()}})


@csrf_exempt
@require_POST
def submit(request, job_id):
    agent = _agent(request)
    if agent is None:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        body = _body(request)
        lease = body["lease"]
        result = body["result"]
        if not isinstance(lease, str) or len(lease) > 128 or not isinstance(result, dict):
            raise ValueError("Invalid result")
        if result.get("status") not in ("success", "error"):
            raise ValueError("Invalid result status")
    except (KeyError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "invalid request"}, status=400)
    now = timezone.now()
    updated = ContextJob.objects.filter(pk=job_id, agent=agent, status="claimed", expires_at__gt=now,
        claimed_at__gte=now-timedelta(minutes=5), lease_hash=hashlib.sha256(lease.encode()).hexdigest()).update(
        status="completed" if result["status"] == "success" else "failed", result=result, completed_at=now, lease_hash="")
    return JsonResponse({"ok": bool(updated)}, status=200 if updated else 409)
