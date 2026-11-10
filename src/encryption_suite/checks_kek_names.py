"""
Deploy-time checks that keep two silos from sharing one key encryption key (KEK).

A KEK name comes from a store's ``KEK_TEMPLATE`` or ``KEK_MAP`` and the silo uid.
Deleting a KEK shreds every silo whose data keys sit under it, so two silos that
reach one name lose their data together. These checks read configuration only and
need no running application. They apply to stores whose strategy is
``PerSiloKekStrategy`` or a subclass; any other strategy is exempt, because the
package cannot know what it does.

Ids: ``E042`` one silo adapter per store, ``E043`` a template needs a literal
prefix, ``E044`` duplicate values in a destroyable ``KEK_MAP``, ``E045`` a map
value another store can name, ``E046`` a map value its own store's template can
name, ``W059`` duplicate values in an unflagged ``KEK_MAP``. A message names the
store or key sets involved and carries no hint: ``docs/configuration.md`` holds the
guidance.
"""

from __future__ import annotations

from django.core.checks import Error as CheckError
from django.core.checks import Warning as CheckWarning
from django.core.checks import register
from django.utils.module_loading import import_string

from .conf import adapter_path, configured_setting, key_set_names, resolve_store

E_ONE_ADAPTER = "encryption_suite.E042"
E_NO_PREFIX = "encryption_suite.E043"
E_DUPLICATE_DESTROYABLE = "encryption_suite.E044"
E_REACHES_OTHER_STORE = "encryption_suite.E045"
E_REACHES_OWN_TEMPLATE = "encryption_suite.E046"
W_DUPLICATE_UNFLAGGED = "encryption_suite.W059"

#: Every id this module reports, for the test that asserts none carries a hint.
CHECK_IDS = (
    E_ONE_ADAPTER,
    E_NO_PREFIX,
    E_DUPLICATE_DESTROYABLE,
    E_REACHES_OTHER_STORE,
    E_REACHES_OWN_TEMPLATE,
    W_DUPLICATE_UNFLAGGED,
)


def is_per_silo_strategy(path) -> bool:
    """Whether the class *path* names is ``PerSiloKekStrategy`` or a subclass of it.

    Imports the class and constructs nothing. A path that does not import is not
    per-silo here; the construction check reports the bad path.
    """
    from .adapters.keks.strategies import PerSiloKekStrategy

    if not isinstance(path, str) or not path:
        return False
    try:
        cls = import_string(path)
    except ImportError:
        return False
    return isinstance(cls, type) and issubclass(cls, PerSiloKekStrategy)


def per_silo_blocks() -> dict[str, dict]:
    """The ``KMS_KEY_STORES`` blocks whose strategy is per-silo, by name."""
    blocks = configured_setting("KMS_KEY_STORES")
    if not isinstance(blocks, dict):
        return {}
    return {
        name: block
        for name, block in blocks.items()
        if isinstance(block, dict) and is_per_silo_strategy(block.get("KEK_STRATEGY_ADAPTER"))
    }


def template_prefix(template) -> str | None:
    """The literal text before ``{silo_uid}`` in *template*, or ``None`` when there is no placeholder."""
    if not isinstance(template, str) or "{silo_uid}" not in template:
        return None
    return template.split("{silo_uid}", 1)[0]


class _Store:
    """One per-silo store's naming settings, read once."""

    def __init__(self, name: str, block: dict):
        options = block.get("OPTIONS") if isinstance(block.get("OPTIONS"), dict) else {}
        template, kek_map = options.get("KEK_TEMPLATE") or "", options.get("KEK_MAP") or {}
        self.name = name
        self.template = template if isinstance(template, str) else ""
        self.kek_map = kek_map if isinstance(kek_map, dict) else {}
        self.destroyable = bool(options.get("KEK_MAP_DESTROYABLE"))
        self.prefix = template_prefix(self.template)
        self.label = f"ENCRYPTION['KMS_KEY_STORES']['{name}']"

    @property
    def map_values(self) -> list[str]:
        return [value for value in self.kek_map.values() if isinstance(value, str)]


def _stores() -> list[_Store]:
    return [_Store(name, block) for name, block in per_silo_blocks().items()]


def _listed(items) -> str:
    items = [repr(item) for item in items]
    return ", ".join(items[:5]) + (f", and {len(items) - 5} more" if len(items) > 5 else "")


def _one_adapter_per_store(stores: list[_Store]) -> list:
    problems = []
    names = key_set_names()
    for store in stores:
        by_adapter: dict[str, list[str]] = {}
        for key_set in names:
            adapter = adapter_path(key_set)
            if adapter and resolve_store(key_set) == store.name:
                by_adapter.setdefault(adapter, []).append(key_set)
        if len(by_adapter) > 1:
            groups = "; ".join(f"{adapter} ({', '.join(sets)})" for adapter, sets in by_adapter.items())
            problems.append(
                CheckError(
                    f"{store.label} serves key sets bound to different silo adapters: {groups}.",
                    id=E_ONE_ADAPTER,
                )
            )
    return problems


def _templates_need_prefix(stores: list[_Store]) -> list:
    if len(stores) < 2:
        return []
    return [
        CheckError(
            f"{store.label} has a KEK_TEMPLATE with no literal prefix before {{silo_uid}}, and more than one "
            "store names keys per silo.",
            id=E_NO_PREFIX,
        )
        for store in stores
        if store.template and not store.prefix
    ]


def _duplicate_values(stores: list[_Store]) -> list:
    problems = []
    for store in stores:
        values = store.map_values
        duplicated = sorted({value for value in values if values.count(value) > 1})
        if not duplicated:
            continue
        message = f"{store.label}['OPTIONS']['KEK_MAP'] maps more than one silo to the key {_listed(duplicated)}."
        if store.destroyable:
            problems.append(CheckError(message, id=E_DUPLICATE_DESTROYABLE))
        else:
            problems.append(CheckWarning(message, id=W_DUPLICATE_UNFLAGGED))
    return problems


def _values_other_stores_can_name(stores: list[_Store]) -> list:
    problems = []
    for store in stores:
        reached: dict[str, list[str]] = {}
        for other in stores:
            if other is store:
                continue
            other_values = set(other.map_values)
            for value in store.map_values:
                if value in other_values or (other.prefix and value.startswith(other.prefix)):
                    reached.setdefault(other.name, []).append(value)
        for other_name, values in reached.items():
            problems.append(
                CheckError(
                    f"{store.label}['OPTIONS']['KEK_MAP'] has {_listed(sorted(set(values)))}, which the store "
                    f"{other_name!r} can name.",
                    id=E_REACHES_OTHER_STORE,
                )
            )
    return problems


def _values_own_template_can_name(stores: list[_Store]) -> list:
    problems = []
    for store in stores:
        if not store.prefix:
            continue
        values = sorted({value for value in store.map_values if value.startswith(store.prefix)})
        if values:
            problems.append(
                CheckError(
                    f"{store.label}['OPTIONS']['KEK_MAP'] has {_listed(values)}, which starts with the "
                    f"store's own KEK_TEMPLATE prefix {store.prefix!r}.",
                    id=E_REACHES_OWN_TEMPLATE,
                )
            )
    return problems


@register()
def check_kek_names_do_not_collide(app_configs, **kwargs):
    """Report configuration that lets two silos reach one KEK.

    Validators, so ``STARTUP_CHECK_WARN_ONLY`` leaves them alone. The comparison
    does not ask whether two stores reach one provider account (``E037`` does not
    either), so two accounts that reuse a prefix get an error they could live with.
    """
    from django.conf import settings

    if not getattr(settings, "ENCRYPTION", None):
        return []
    stores = _stores()
    return [
        *_one_adapter_per_store(stores),
        *_templates_need_prefix(stores),
        *_duplicate_values(stores),
        *_values_other_stores_can_name(stores),
        *_values_own_template_can_name(stores),
    ]
