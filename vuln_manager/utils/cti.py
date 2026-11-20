"""Import limited, configured Heise Atom feeds and propose inventory matches."""
import hashlib
import html
import logging
import re
import ipaddress
import socket
from datetime import timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit, urlunsplit
from datetime import timezone as datetime_timezone

import requests
from defusedxml import ElementTree as ET
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.html import strip_tags
from vuln_manager.models import CTIFeed, CTIItem, CTIMatch, Extension, NotificationEvent, Software, Vulnerability

logger = logging.getLogger(__name__)
FEEDS = {
    "Heise Security Alerts": "https://www.heise.de/security/rss/alert-news-atom.xml",
    "Heise Security News": "https://www.heise.de/security/rss/news-atom.xml",
}
MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def validate_feed_url(url, *, resolve=True):
    """Accept public HTTPS feeds, rejecting local/private destinations at each hop."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None, 443)):
            raise ValueError("Feed URL must use HTTPS on port 443 without credentials")
        if resolve:
            addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(info[4][0]).is_global for info in addresses):
                raise ValueError("Feed URL must resolve to public addresses")
    except (ValueError, socket.gaierror) as exc:
        raise ValueError(f"Invalid public feed URL: {exc}") from exc
    return url


def cti_enabled():
    return Extension.objects.filter(name_id="cti", is_active=True).exists()


def parse_date(value):
    if not value:
        return None
    try:
        date = parse_datetime(value) or parsedate_to_datetime(value)
        if timezone.is_naive(date):
            date = timezone.make_aware(date, datetime_timezone.utc)
        return date
    except (ValueError, TypeError, OverflowError):
        return None


def _text(node, *names):
    for name in names:
        element = node.find(name)
        if element is not None:
            return " ".join(element.itertext()).strip()
    return ""


def parse_feed(data):
    root = ET.fromstring(data)
    atom = "{http://www.w3.org/2005/Atom}"
    rss1 = "{http://purl.org/rss/1.0/}"
    if root.tag not in {atom + "feed", "rss", "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF"}:
        raise ValueError("Unsupported feed format")
    entries = root.findall(atom + "entry") or root.findall(".//item") or root.findall(".//" + rss1 + "item")
    for entry in entries:
        links = entry.findall(atom + "link")
        link_node = next((node for node in links if node.get("rel", "alternate") == "alternate"), None)
        link = link_node.get("href", "") if link_node is not None else _text(entry, "link", rss1 + "link")
        parsed = urlsplit(link)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            continue
        query = "" if parsed.hostname == "heise.de" or parsed.hostname.endswith(".heise.de") else parsed.query
        link = urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path, query, ""))
        if len(link) > 1000:
            continue
        title = html.unescape(strip_tags(_text(entry, atom + "title", "title", rss1 + "title")))[:500]
        summary = html.unescape(strip_tags(_text(entry, atom + "summary", "description", rss1 + "description")))[:4000]
        if not title:
            continue
        yield {
            "external_id": hashlib.sha256(link.encode()).hexdigest(), "url": link,
            "title": title, "summary": summary,
            "published_at": parse_date(_text(entry, atom + "published", "pubDate")),
            "updated_at": parse_date(_text(entry, atom + "updated")),
            "cves": sorted({v.upper() for v in CVE_RE.findall(title + " " + summary)}),
        }


def suggest_matches(item):
    text = item.title + " " + item.summary
    candidates = set()
    matched_ids = []
    for vuln in Vulnerability.objects.filter(cve_id__in=item.cves).iterator():
        if vuln.software_id:
            candidates.add(vuln.software_id)
        NotificationEvent.objects.get_or_create(
            key=f"cti:{item.pk}:vuln:{vuln.pk}",
            defaults={"event_type": "cti_match", "title": item.title, "item": item, "vulnerability": vuln, "software_id": vuln.software_id},
        )
    for software in Software.objects.all().iterator():
        name = (software.name or "").strip()
        by_name = len(name) >= 4 and bool(re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", text, re.I))
        if software.pk not in candidates and not by_name:
            continue
        matched_ids.append(software.pk)
        reason = "CVE matches existing finding" if software.pk in candidates else f"Product name: {name}; version not verified"
        match, created = CTIMatch.objects.get_or_create(item=item, software=software, defaults={"reason": reason})
        if not created and match.reason != reason:
            match.reason = reason
            match.save(update_fields=["reason"])
        if created and software.pk not in candidates:
            NotificationEvent.objects.get_or_create(key=f"cti:{item.pk}:software:{software.pk}", defaults={"event_type": "cti_match", "title": item.title, "item": item, "software": software})
    CTIMatch.objects.filter(item=item).exclude(software_id__in=matched_ids).delete()


def fetch_feed(feed):
    url = feed.url
    for redirect_count in range(MAX_REDIRECTS + 1):
        validate_feed_url(url)
        response = requests.get(url, timeout=20, stream=True, allow_redirects=False, headers={"User-Agent": "CVE3PO CTI feed reader"})
        if response.status_code not in (301, 302, 303, 307, 308):
            break
        try:
            location = response.headers.get("Location")
            if not location:
                raise ValueError("Feed redirect has no Location header")
            if redirect_count == MAX_REDIRECTS:
                raise ValueError("Too many feed redirects")
            url = urljoin(url, location)
            validate_feed_url(url)
        finally:
            response.close()
    try:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError(f"Unexpected HTTP status {response.status_code}")
        content = bytearray()
        for chunk in response.iter_content(65536):
            content.extend(chunk)
            if len(content) > MAX_BYTES:
                raise ValueError("Feed exceeds size limit")
        items = list(parse_feed(bytes(content)))
    finally:
        response.close()
    for data in items:
        with transaction.atomic():
            item, _ = CTIItem.objects.update_or_create(external_id=data.pop("external_id"), defaults={**data, "source": feed})
            suggest_matches(item)
    return len(items)


def run_feeds():
    if not cti_enabled():
        return
    now = timezone.now()
    polled = False
    for feed in CTIFeed.objects.filter(enabled=True):
        # Atomic claim limits polling to once an hour across web workers.
        from django.db.models import Q
        claimed = CTIFeed.objects.filter(pk=feed.pk).filter(Q(last_attempt__isnull=True) | Q(last_attempt__lt=now - timedelta(hours=1))).update(last_attempt=now)
        if not claimed:
            continue
        polled = True
        try:
            fetch_feed(feed)
            CTIFeed.objects.filter(pk=feed.pk).update(last_success=timezone.now(), last_error="")
        except Exception as exc:
            logger.exception("CTI feed failed: %s", feed.name)
            CTIFeed.objects.filter(pk=feed.pk).update(last_error=str(exc)[:500])
    # Re-evaluate recent items for software added since the last feed poll.
    if polled:
        for item in CTIItem.objects.filter(received_at__gte=now-timedelta(days=30)).iterator():
            suggest_matches(item)
