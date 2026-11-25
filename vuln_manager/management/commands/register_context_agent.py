import hashlib
import secrets

from django.core.management.base import BaseCommand, CommandError
from vuln_manager.models import ContextAgent, Host


class Command(BaseCommand):
    help = "Create or rotate a separate per-host context agent credential."

    def add_arguments(self, parser):
        parser.add_argument("host_id", type=int)
        parser.add_argument("--rotate", action="store_true")

    def handle(self, host_id, rotate, **options):
        host = Host.objects.filter(pk=host_id).first()
        if not host:
            raise CommandError("Host not found")
        if ContextAgent.objects.filter(host=host).exists() and not rotate:
            raise CommandError("Agent already exists; use --rotate to invalidate its token")
        token = secrets.token_urlsafe(48)
        ContextAgent.objects.update_or_create(host=host, defaults={"token_hash": hashlib.sha256(token.encode()).hexdigest(), "enabled": True})
        self.stdout.write("Context agent token (shown once): " + token)
