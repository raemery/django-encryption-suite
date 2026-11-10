"""
Management command: encryption_suite_rotate_hashicorp_approle

Generates a fresh AppRole ``secret_id`` for a configured Vault role and prints
the result as JSON on stdout. Designed to be called from a privileged
context — CI/CD, an ops workstation, or a scheduled job with elevated
credentials — NEVER from the application workloads that consume the
secret_id. The app uses the rotated secret_id; it does not rotate it for
itself (doing so would defeat AppRole).

This is the "trusted orchestrator" pattern from HashiCorp's
`Secure introduction of Vault clients
<https://developer.hashicorp.com/vault/tutorials/app-integration/secure-introduction>`_
tutorial. With ``--wrap``, the command instead emits a single-use response
wrapping token that the workload unwraps once at startup — the canonical
secure introduction mechanism, since the raw secret_id never traverses
the delivery channel.

Usage::

    # Plain secret_id, piped into your secrets manager.
    VAULT_ADDR=https://vault.example.com:8200 \\
    VAULT_TOKEN=<admin token> \\
    VAULT_NAMESPACE=admin \\
        python manage.py encryption_suite_rotate_hashicorp_approle --role encryption_suite \\
        | jq -r .secret_id \\
        | xargs -I {} fly secrets set -a my-app VAULT_SECRET_ID={}

    # Response-wrapped secret_id (5-minute single-use wrapping token).
    python manage.py encryption_suite_rotate_hashicorp_approle \\
        --role encryption_suite --wrap --wrap-ttl 5m

Required environment / arguments:
  --role <name>            AppRole role name (e.g. "encryption_suite")
  VAULT_ADDR (env)         or --vault-addr <url>
  VAULT_TOKEN (env)        admin token; or --admin-token <token>

Optional:
  VAULT_NAMESPACE (env)    or --vault-namespace <ns> (HCP Vault / Enterprise)
  --approle-mount <path>   Vault AppRole mount path (default: "approle")
  --wrap                   Emit a response-wrapping token instead of the raw secret_id.
  --wrap-ttl <duration>    Wrapping token TTL (default: "5m"). Only used with --wrap.

Output (JSON on stdout):
  Without --wrap:
    {"secret_id": "...", "secret_id_accessor": "...", "secret_id_ttl": N,
     "secret_id_num_uses": N, "expiration_time": "..."}

  With --wrap:
    {"wrapping_token": "...", "wrapping_token_ttl": N,
     "wrapping_token_accessor": "...", "creation_path": "..."}
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from django.core.management.base import BaseCommand, CommandError

from encryption_suite._logging import get_logger

logger = get_logger(__name__)


class Command(BaseCommand):
    help = (
        "Generate a fresh AppRole secret_id for a Vault role. Intended for "
        "privileged orchestrator contexts (CI, scheduled jobs); not for app "
        "workloads."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--role",
            required=True,
            help="AppRole role name (e.g. 'encryption_suite').",
        )
        parser.add_argument(
            "--vault-addr",
            default=None,
            help="Vault server URL. Defaults to the VAULT_ADDR env var.",
        )
        parser.add_argument(
            "--admin-token",
            default=None,
            help="Admin Vault token. Defaults to the VAULT_TOKEN env var.",
        )
        parser.add_argument(
            "--vault-namespace",
            default=None,
            help="Vault namespace (HCP Vault / Enterprise). Defaults to the VAULT_NAMESPACE env var.",
        )
        parser.add_argument(
            "--approle-mount",
            default="approle",
            help="AppRole auth method mount path (default: 'approle').",
        )
        parser.add_argument(
            "--wrap",
            action="store_true",
            help="Emit a response-wrapping token instead of the raw secret_id. "
            "The workload unwraps once at startup via /sys/wrapping/unwrap.",
        )
        parser.add_argument(
            "--wrap-ttl",
            default="5m",
            help="Wrapping token TTL (Vault duration string; default: '5m'). Only used with --wrap.",
        )

    def handle(self, *args, **options):
        from encryption_suite.user_context import get_os_user, identity_tail

        # The role and mount only: this command also takes an admin Vault token,
        # which must never reach a log.
        logger.warning(
            "A privileged management command started; this line records that it ran, including a run "
            'that changes nothing. command=encryption_suite_rotate_hashicorp_approle role="%s" mount="%s" %s',
            options["role"],
            options["approle_mount"],
            identity_tail(os_login_user=get_os_user()),
        )

        def log_finished(issued: int, accessor: str = "") -> None:
            """Close the run, at the level its opening line was written at.

            This command writes no ledger row and prints its result to standard
            output, so these two lines are the whole record that a credential was
            rotated. The accessor names the secret-id Vault now holds without
            being usable to authenticate as it — the secret-id itself, and the
            admin token, must never reach a log.
            """
            logger.warning(
                'A privileged management command finished. command=encryption_suite_rotate_hashicorp_approle role="%s" '
                'mount="%s" wrapped=%s issued=%d accessor="%s" %s',
                options["role"],
                options["approle_mount"],
                options["wrap"],
                issued,
                accessor,
                identity_tail(os_login_user=get_os_user()),
            )

        addr = options["vault_addr"] or os.environ.get("VAULT_ADDR")
        token = options["admin_token"] or os.environ.get("VAULT_TOKEN")
        namespace = options["vault_namespace"] or os.environ.get("VAULT_NAMESPACE")
        if not addr:
            log_finished(0)
            raise CommandError("VAULT_ADDR not set. Pass --vault-addr or set the env var.")
        if not token:
            log_finished(0)
            raise CommandError(
                "VAULT_TOKEN not set. Pass --admin-token or set the env var. "
                "This must be an admin-shaped token with permission to call "
                "the AppRole secret-id endpoint."
            )

        mount = urllib.parse.quote(options["approle_mount"], safe="")
        role = urllib.parse.quote(options["role"], safe="")
        url = f"{addr.rstrip('/')}/v1/auth/{mount}/role/{role}/secret-id"

        headers = {
            "X-Vault-Token": token,
            "Content-Type": "application/json",
        }
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        if options["wrap"]:
            headers["X-Vault-Wrap-TTL"] = options["wrap_ttl"]

        req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            log_finished(0)
            raise CommandError(f"Vault returned {exc.code} {exc.reason} for {url}: {body}") from exc
        except urllib.error.URLError as exc:
            log_finished(0)
            raise CommandError(f"Failed to reach Vault at {url}: {exc}") from exc

        if options["wrap"]:
            wrap_info = payload.get("wrap_info") or {}
            output = {
                "wrapping_token": wrap_info.get("token"),
                "wrapping_token_ttl": wrap_info.get("ttl"),
                "wrapping_token_accessor": wrap_info.get("accessor"),
                "creation_path": wrap_info.get("creation_path"),
            }
        else:
            data = payload.get("data") or {}
            output = {
                "secret_id": data.get("secret_id"),
                "secret_id_accessor": data.get("secret_id_accessor"),
                "secret_id_ttl": data.get("secret_id_ttl"),
                "secret_id_num_uses": data.get("secret_id_num_uses"),
                "expiration_time": data.get("expiration_time"),
            }
        self.stdout.write(json.dumps(output))
        accessor = output["wrapping_token_accessor"] if options["wrap"] else output["secret_id_accessor"]
        log_finished(1, accessor or "")
