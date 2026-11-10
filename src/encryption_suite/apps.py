from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

from ._logging import get_logger

logger = get_logger(__name__)


def _silo_uid_for(instance, key_set: str = "default") -> str:
    """The silo UID for *instance*, or ``"?"`` when the adapter cannot give one.

    Only for a failure line: the UID is what every other line names a silo by,
    and a lookup that fails here must not replace the failure being reported.
    """
    try:
        from encryption_suite.registry import get_silo_adapter

        return get_silo_adapter(key_set).get_silo_uid(instance)
    except Exception:
        return "?"


class EncryptionConfig(AppConfig):
    name = "encryption_suite"
    verbose_name = _("Encryption")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        self._register_auto_create_signals()
        self._register_deletion_signals()
        self._check_test_console_sentinel()
        self._install_admin_ordering()
        # Importing registers the @register-decorated check.
        from . import checks  # noqa: F401

    @staticmethod
    def _install_admin_ordering() -> None:
        """Order this app's models in the admin index (see admin_site)."""
        from .admin_site import install_app_ordering

        install_app_ordering()

    @staticmethod
    def _check_test_console_sentinel() -> None:
        """Verify no key set's silo adapter can resolve to a reserved test UID.

        Runs only the no-DB portion here (current request context, which
        during app init is always empty but is cheap to check and catches
        a pathological adapter that hard-codes the sentinel UID). The
        DB-enumerating branch runs lazily on first test-console view
        access — see `admin.DataEncryptionKeyAdmin._ensure_sentinel_check`.
        """
        try:
            from .registry import silo_adapter_groups
            from .test_console import (
                ConsoleSentinelLeakError,
                assert_sentinel_not_producible_no_db,
            )
        except Exception:
            return
        try:
            adapters = [adapter for adapter, _key_sets in silo_adapter_groups()]
        except Exception as exc:
            logger.debug('The test-console sentinel check was skipped. stage=adapter_load detail="%s"', exc)
            return
        for adapter in adapters:
            try:
                assert_sentinel_not_producible_no_db(adapter)
            except ConsoleSentinelLeakError:
                raise
            except Exception as exc:
                logger.debug('The test-console sentinel check was skipped. detail="%s"', exc)

    @staticmethod
    def _silo_models(setting: str, key_set: str):
        """The silo models of *key_set*'s adapter, or an empty list after logging why there are none.

        The adapter declares its silo models (``silo_model_labels``); one that
        declares none cannot use ``SILO_AUTO_KEY_CREATION`` or ``SILO_AUTO_KEY_DELETION``.
        """
        from django.apps import apps as django_apps

        from ._internal import operator_error_text
        from .registry import get_silo_adapter

        try:
            labels = get_silo_adapter(key_set).silo_model_labels
        except Exception as exc:
            logger.warning(
                "A key set named in %s has no silo adapter that can be built, so nothing is registered "
                'for it. key_set="%s" detail="%s"',
                setting,
                key_set,
                operator_error_text(exc),
            )
            return []
        if not labels:
            logger.warning(
                "The silo adapter of a key set named in %s declares no silo models, so nothing is "
                'registered for it. key_set="%s"',
                setting,
                key_set,
            )
            return []
        models = []
        for label in labels:
            try:
                models.append(django_apps.get_model(label))
            except (LookupError, ValueError):
                logger.warning(
                    "A silo model declared by the silo adapter of a key set named in %s could not be "
                    'found. key_set="%s" model="%s"',
                    setting,
                    key_set,
                    label,
                )
        return models

    def _register_auto_create_signals(self) -> None:
        """
        For each key set listed in ENCRYPTION['SILO_AUTO_KEY_CREATION'], register a
        post_save signal on the silo models of that key set's adapter that
        generates the key set's field DEK when a new silo is created.

        ENCRYPTION = {
            ...
            "SILO_AUTO_KEY_CREATION": ["default"],
        }
        """
        from django.conf import settings

        config = getattr(settings, "ENCRYPTION", {})
        key_sets = config.get("SILO_AUTO_KEY_CREATION", [])
        if not key_sets:
            return

        from django.db.models.signals import post_save

        def _make_handler(key_set):
            def _handler(sender, instance, created, **kwargs):
                if not created:
                    return
                try:
                    from encryption_suite.registry import get_engine

                    # The engine logs the creation itself, beside its ledger row.
                    get_engine().generate_and_store_keyset(instance, key_set=key_set)
                except Exception:
                    # One clean English line, no traceback and no detail: the raise
                    # site already logged the operator detail under its error code,
                    # and a stack trace here walks through package internals, which
                    # wrongly implicates the consuming project's code for a failure
                    # in a dependency it does not maintain.
                    logger.error(
                        "A silo was created but its encryption keyset could not be provisioned; the "
                        "silo has no key, and the next encrypt will provision one only where "
                        'KEY_AUTO_PROVISION allows it. key_set="%s" silo="%s"',
                        key_set,
                        _silo_uid_for(instance, key_set),
                    )

            return _handler

        for key_set in key_sets:
            for model in self._silo_models("SILO_AUTO_KEY_CREATION", key_set):
                post_save.connect(
                    _make_handler(key_set),
                    sender=model,
                    weak=False,
                    dispatch_uid=f"encrypted_fields_auto_create_{key_set}_{model._meta.label}",
                )
                logger.debug(
                    'Registered the data-key provisioning signal. key_set="%s" model="%s"', key_set, model._meta.label
                )

    def _register_deletion_signals(self) -> None:
        """
        For each key set listed in ENCRYPTION['SILO_AUTO_KEY_DELETION'], register a
        post_delete signal on the silo models of that key set's adapter that
        *schedules* key deletion for the deleted silo: its DEK rows in every key set
        bound to the adapter (and any silo-exclusive KEK) are flipped to
        `deletion_scheduled` inside the soft-delete window. Scheduling
        destroys nothing — the admin purge action processes expired work
        later through the deletion gates, and a restore reverses it meanwhile.

        Listing a key set selects its adapter; the deletion never covers fewer key
        sets than the adapter has, because keys left behind by a deleted silo are
        never wanted. Two listed key sets of one adapter register one handler.

        ENCRYPTION = {
            ...
            "SILO_AUTO_KEY_DELETION": ["default"],
        }
        """
        from django.conf import settings

        config = getattr(settings, "ENCRYPTION", {})
        key_sets = config.get("SILO_AUTO_KEY_DELETION", [])
        if not key_sets:
            return

        from django.db.models.signals import post_delete

        from .conf import adapter_path

        def _make_handler(key_set):
            def _handler(sender, instance, **kwargs):
                # A receiver must never raise out of a delete — that would break
                # the operator's delete transaction. schedule_deletion funnels its
                # own failures into a typed EncryptionError, logging one clean
                # error_code=kek_deletion_record_failed line (no traceback), so here we only
                # catch and swallow: the delete proceeds and the un-scheduled KEK
                # stays recoverable via the KMS-side reconcile path. The
                # bare-Exception arm is a backstop for anything raised before the
                # funnel (e.g. resolving the silo adapter).
                from encryption_suite.exceptions import EncryptionError, log_and_raise_deletion_record_error

                try:
                    from encryption_suite.deletion import schedule_deletion
                    from encryption_suite.registry import get_silo_adapter
                    from encryption_suite.silo_ref import SiloRef

                    schedule_deletion(SiloRef(key_set, get_silo_adapter(key_set).get_silo_uid(instance)))
                except EncryptionError:
                    pass
                except Exception as exc:
                    try:
                        log_and_raise_deletion_record_error(
                            logger,
                            f"Failed to record KEK deletion event for {sender.__name__} pk={instance.pk}: {exc}",
                            cause=exc,
                        )
                    except EncryptionError:
                        pass

            return _handler

        registered = set()
        for key_set in key_sets:
            path = adapter_path(key_set)
            if path in registered:
                continue
            registered.add(path)
            for model in self._silo_models("SILO_AUTO_KEY_DELETION", key_set):
                post_delete.connect(
                    _make_handler(key_set),
                    sender=model,
                    weak=False,
                    dispatch_uid=f"encryption_suite_deletion_on_delete_{path}_{model._meta.label}",
                )
                logger.debug('Registered the key deletion signal. key_set="%s" model="%s"', key_set, model._meta.label)
