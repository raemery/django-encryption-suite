"""Optional, framework-specific integrations for django-encryption-suite.

Modules here are opt-in adapters that keep the core package
presentation-neutral: they consume the core's structured signals
(``exc.code``, ``is_undecryptable`` / the per-instance ``_encryption_suite_errors``
map) and render them for a specific framework.

A module here takes its own optional dependency extra where it imports the
framework (``[drf]`` for :mod:`encryption_suite.contrib.drf`), and none where it
does not: :mod:`encryption_suite.contrib.allauth` is an adapter mixin for the MFA
secrets django-allauth routes through its adapter, and imports nothing from it.

:mod:`encryption_suite.contrib.simpleteams` is an installable app rather than an
adapter for a framework: a team model, its silo adapter, middleware and admin,
for projects with no team model of their own. It needs no extra.
"""
