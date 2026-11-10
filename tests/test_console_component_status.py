"""A failed console test only reds the layer it is actually evidence against.

The console's tests are layered: ``field_full`` exercises the crypto backend
*and* the KMS. Blaming every touched component for a failure meant one KMS
outage turned the backend box red even though ``field_memory`` had just proved
the backend healthy — and left it red until the results were cleared.
"""

from __future__ import annotations

from encryption_suite.admin_test_console import _compute_component_status


def _results(**statuses: str) -> dict:
    return {tid: {"status": status, "detail": ""} for tid, status in statuses.items()}


def test_untested_components_are_none():
    assert _compute_component_status({}) == {"backend": None, "kms": None, "storage": None}


def test_kms_failure_leaves_a_proven_backend_green():
    status = _compute_component_status(
        _results(field_memory="pass", file_memory="pass", field_full="fail"),
    )
    assert status["backend"] == "pass"
    assert status["kms"] == "fail"
    assert status["storage"] is None


def test_backend_own_test_failure_still_reds_the_backend():
    status = _compute_component_status(_results(field_memory="fail"))
    assert status["backend"] == "fail"


def test_unblamed_failure_alone_is_not_read_as_healthy():
    # Only the KMS-layer test has run, so nothing has proved the backend good.
    status = _compute_component_status(_results(field_full="fail"))
    assert status["backend"] == "fail"
    assert status["kms"] == "fail"


def test_running_the_memory_tests_afterwards_clears_the_backend():
    status = _compute_component_status(
        _results(field_full="fail", field_memory="pass", file_memory="pass"),
    )
    assert status["backend"] == "pass"
    assert status["kms"] == "fail"


class TestTagSummary:
    """The KMS box shows the configured tags, not just how many there are.

    A wrong value is likelier than a missing setting, and it stays invisible
    until a key is created — by which point the tag is written and, on Azure and
    GCP, only rewritable by recreating the key.
    """

    @staticmethod
    def _status(tags=(), namespaces=(), supported=True):
        from encryption_suite.adapters.keks.provisioners import TaggingStatus

        return TaggingStatus(
            tag_count=len(tags),
            tags=tuple(tags),
            defined_tag_namespace_count=len(namespaces),
            defined_tag_namespaces=tuple(namespaces),
            supported=supported,
        )

    def test_pairs_are_shown(self):
        from encryption_suite.admin_test_console import _summarize_tags

        line = _summarize_tags(self._status((("app", "secure-share"), ("managed-by", "suite"))))

        assert line == "app=secure-share, managed-by=suite"

    def test_a_long_value_is_truncated_before_it_crowds_the_others(self):
        from encryption_suite.admin_test_console import _summarize_tags

        line = _summarize_tags(self._status((("note", "x" * 50), ("app", "ss"))))

        assert "app=ss" in line
        assert "…" in line

    def test_many_tags_degrade_to_a_remainder_count(self):
        from encryption_suite.admin_test_console import _summarize_tags

        tags = tuple((f"key{n}", f"value{n}") for n in range(12))

        line = _summarize_tags(self._status(tags))

        assert line.endswith(")")
        assert "+" in line.rsplit("(", 1)[1]
        assert len(line) < 90

    def test_the_first_tag_survives_a_width_smaller_than_itself(self):
        # Never render an empty line: one item is always shown, however long.
        from encryption_suite.admin_test_console import _summarize_tags

        line = _summarize_tags(self._status((("app", "ss"), ("b", "c"))), width=3)

        assert line.startswith("app=ss")
        assert line.endswith("(+1)")

    def test_defined_tag_namespaces_are_named_not_expanded(self):
        # OCI's are nested; naming them is what an operator checks.
        from encryption_suite.admin_test_console import _summarize_tags

        line = _summarize_tags(self._status((("app", "ss"),), namespaces=("Operations",)))

        assert line == "app=ss, Operations:*"


class _Request:
    def __init__(self):
        self.session = {}


def test_kms_results_are_kept_per_kms_and_the_rest_shared():
    from encryption_suite.admin_test_console import _results_for, _store_results

    request = _Request()
    _store_results(request, "fly", _results(field_memory="pass", field_full="fail"))
    _store_results(request, "system", _results(field_full="pass"))

    assert _results_for(request, "fly") == _results(field_memory="pass", field_full="fail")
    assert _results_for(request, "system") == _results(field_memory="pass", field_full="pass")


def test_run_all_replaces_only_its_own_kms_results():
    from encryption_suite.admin_test_console import _results_for, _store_results

    request = _Request()
    _store_results(request, "fly", _results(field_full="fail", file_full="fail"))
    _store_results(request, "system", _results(field_full="pass"))
    _store_results(request, "fly", _results(field_memory="pass"), replace=True)

    assert _results_for(request, "fly") == _results(field_memory="pass")
    assert _results_for(request, "system") == _results(field_memory="pass", field_full="pass")
