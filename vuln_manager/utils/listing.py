"""Shared helpers for list views: server-side sorting across the full dataset.

Used by every list view so column headers can sort the whole queryset (not just
the current page). The template renders sort links with the ``_sort_th.html``
partial and the ``qs_replace`` template tag.
"""


def apply_sort(request, queryset, allowed, default_key, default_dir="asc"):
    """Order ``queryset`` from ``?sort=`` / ``?dir=`` against an allow-list.

    Args:
        request: the current HttpRequest (reads GET params).
        queryset: the queryset to order.
        allowed: dict mapping a sort key (used in the URL) to an ORM field
            name, or a list/tuple of field names for tie-breakers.
        default_key: key from ``allowed`` to use when none/invalid is given.
        default_dir: ``"asc"`` or ``"desc"`` when no direction is given.

    Returns:
        (ordered_queryset, sort_state) where sort_state is
        ``{"key": <key>, "dir": "asc"|"desc"}`` for the template.
    """
    key = request.GET.get("sort") or default_key
    if key not in allowed:
        key = default_key

    direction = (request.GET.get("dir") or default_dir).lower()
    if direction not in ("asc", "desc"):
        direction = default_dir

    fields = allowed[key]
    if isinstance(fields, str):
        fields = [fields]

    prefix = "-" if direction == "desc" else ""
    order = [f"{prefix}{f}" for f in fields]

    return queryset.order_by(*order), {"key": key, "dir": direction}
