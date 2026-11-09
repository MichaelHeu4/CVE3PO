"""Fixed-vulnerability lifecycle helpers: keep ``fixed_at`` in sync with status
and delete fixed vulnerabilities in bulk.

Both the manual "delete fixed" button and the Auto-Delete-Fixed scheduler use
``bulk_delete_fixed_vulnerabilities`` so deletion and auditing behave the same
way everywhere.
"""

from django.db import transaction
from django.utils import timezone

from vuln_manager.models import Vulnerability, VulnerabilityAuditEvent

# Delete in batches so memory stays bounded and the SQLite write lock is not
# held open across the whole table on large datasets.
_DELETE_BATCH_SIZE = 1000


def stamp_fixed_at(vuln):
    """Synchronise ``vuln.fixed_at`` with ``vuln.status`` in memory.

    Call this right before saving whenever the status may have changed. Returns
    ``True`` if ``fixed_at`` was modified, so callers using ``update_fields`` know
    to include ``"fixed_at"``.
    """
    if vuln.status == "fixed":
        if vuln.fixed_at is None:
            vuln.fixed_at = timezone.now()
            return True
        return False
    if vuln.fixed_at is not None:
        vuln.fixed_at = None
        return True
    return False


def bulk_delete_fixed_vulnerabilities(
    queryset=None, *, user=None, actor=None, tag="fixed", batch_size=_DELETE_BATCH_SIZE
):
    """Delete fixed vulnerabilities in batches, writing one audit event each.

    Args:
        queryset: vulnerabilities to delete; defaults to all ``status="fixed"``.
        user / actor: attribution for the audit events.
        tag: value stored in ``details["bulk"]`` to mark why they were removed.
        batch_size: rows per batch.

    Returns the number of vulnerabilities deleted.
    """
    if queryset is None:
        queryset = Vulnerability.objects.filter(status="fixed")

    deleted_total = 0
    with transaction.atomic():
        while True:
            batch = list(queryset.values("id", "cve_id", "name")[:batch_size])
            if not batch:
                break

            # One bulk INSERT per batch instead of N single inserts. The audit
            # rows are intentionally detached (vulnerability=None): the delete
            # below would SET_NULL them anyway, and the identifying data is kept
            # in ``details``.
            VulnerabilityAuditEvent.objects.bulk_create(
                [
                    VulnerabilityAuditEvent(
                        vulnerability=None,
                        user=user,
                        actor=actor,
                        action="deleted",
                        details={
                            "cve_id": row["cve_id"],
                            "name": row["name"],
                            "bulk": tag,
                        },
                    )
                    for row in batch
                ]
            )

            batch_ids = [row["id"] for row in batch]
            Vulnerability.objects.filter(id__in=batch_ids).delete()
            deleted_total += len(batch_ids)

    return deleted_total
