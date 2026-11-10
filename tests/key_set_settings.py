"""Builds the ``KEY_SETS`` setting the suite's tests vary."""

GROUP_ADAPTER = "tests.silo.GroupSiloAdapter"


def key_sets(default="local", system="login", **others):
    """The suite's ``KEY_SETS``: ``default`` on the test group adapter and *default*'s store, ``system`` on *system*'s.

    Each of *others* adds a key set of that name on the test group adapter, with the
    store the value names.
    """
    sets = {"default": {"silo": GROUP_ADAPTER, "key_store": default}, "system": {"key_store": system}}
    sets.update({name: {"silo": GROUP_ADAPTER, "key_store": store} for name, store in others.items()})
    return sets
