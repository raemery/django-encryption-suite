"""A ready-made silo for projects that have no team or tenant model of their own.

Ships the model, the silo adapter, the middleware and the admin, so a project
with users and nothing to group them by can encrypt per team without writing
any of the four::

    INSTALLED_APPS = [..., "encryption_suite", "encryption_suite.contrib.simpleteams"]

    MIDDLEWARE = [
        ...,
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware",
    ]

    ENCRYPTION = {
        "KEY_SETS": {
            "default": {
                "silo": "encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter",
                "key_store": "...",
            },
        },
        ...
    }

An app rather than part of the core because it creates tables, and the package
must not create tables nobody asked for. It imports no third-party framework, so
it needs no extra.

Each user belongs to at most one team, enforced by the schema. A project whose
users need several teams wants ``GenericModelSiloAdapter`` over a model of its
own instead. See ``docs/silo-adapters.md``.
"""
