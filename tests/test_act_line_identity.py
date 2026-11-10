"""Every log line reporting an act on a key names who performed it.

A line that reports an act writes `event=<verb>`, pairing it with the ledger row
the same act produced. The row records who acted; the line must say the same, or
the two registers disagree about an act whose author was never in doubt.

Nothing enforces that at the call site: the tail is an ordinary argument spliced
into the format string, so forgetting it costs a trailing `%s` and fails
silently. This guard is what catches that — it reads the source rather than
running the sites, since several are reached only from a provider failure.

The adapters are outside it. They log acts too — a key created, material
destroyed at the provider — but naming an actor there would mean a ``user``
argument on provider methods, which is the wrong layer. Those lines pair with
the attributed one their caller emits about the same act, by key name and time.

The second guard holds every management command to one line of its own: a
WARNING naming the command and who ran it, logged as it starts. A run that
changes nothing writes no ledger row, so without that line it leaves no trace.
"""

from __future__ import annotations

import ast
from pathlib import Path

import encryption_suite

SRC = Path(encryption_suite.__file__).parent

#: Provider code, held to the layer rule rather than this one.
EXCLUDED = "adapters"

#: The helper a site calls to render the identity it holds.
TAIL = "identity_tail"


def _message(call: ast.Call) -> str:
    """The literal text of a logging call's message, or ``""`` if it is dynamic.

    Adjacent string literals are already one constant by parse time, so the
    common multi-line message arrives whole.
    """
    if not call.args:
        return ""
    node = call.args[0]
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _is_log_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"info", "warning"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "logger"
    )


def _names_the_tail(call: ast.Call) -> bool:
    return any(
        isinstance(inner, ast.Call)
        and (
            (isinstance(inner.func, ast.Attribute) and inner.func.attr == TAIL)
            or (isinstance(inner.func, ast.Name) and inner.func.id == TAIL)
        )
        for inner in ast.walk(call)
    )


def _act_lines_without_identity():
    for path in sorted(SRC.rglob("*.py")):
        if EXCLUDED in path.relative_to(SRC).parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not _is_log_call(node):
                continue
            if "event=" not in _message(node):
                continue
            if not _names_the_tail(node):
                yield f"{path.relative_to(SRC)}:{node.lineno}"


def test_every_act_reporting_line_carries_an_identity():
    missing = list(_act_lines_without_identity())
    assert not missing, (
        "these lines report an act on a key without naming who performed it; "
        f"pass identity_tail(...) as the last argument: {missing}"
    )


def test_the_guard_can_see_a_line_that_is_missing_one():
    """A guard that cannot fail proves nothing about the lines it passes."""
    offending = ast.parse('logger.warning("Key material was destroyed. event=%s", verb)')
    call = next(n for n in ast.walk(offending) if _is_log_call(n))
    assert "event=" in _message(call)
    assert not _names_the_tail(call)


# --- Every management command announces itself ------------------------------

COMMANDS = SRC / "management" / "commands"


def _handle(tree: ast.AST):
    """The ``Command`` class's ``handle`` and the methods it calls on ``self``, or ``None``.

    A command that runs one pass per key moves its body into a method ``handle``
    calls once per pass, and the opening line moves with it. Following those
    calls one level keeps such a command under the guard.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Command":
            methods = {item.name: item for item in node.body if isinstance(item, ast.FunctionDef)}
            handle = methods.get("handle")
            if handle is None:
                return None
            called = {
                call.func.attr
                for call in ast.walk(handle)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "self"
            }
            return [handle, *(methods[name] for name in sorted(called) if name in methods)]
    return None


def _announces_itself(functions) -> bool:
    """Whether *functions* log a WARNING naming the command and who ran it."""
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "warning"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "logger"
        and "command=" in _message(node)
        and _names_the_tail(node)
        for function in functions
        for node in ast.walk(function)
    )


def test_every_management_command_announces_itself():
    """A privileged command logs its own start, at WARNING, with the identity tail.

    The line can be the only evidence a run happened: one that changes nothing
    writes no ledger row. A command added without it would run silently, and
    nothing else in the suite would notice.
    """
    checked, missing = 0, []
    for path in sorted(COMMANDS.glob("*.py")):
        handle = _handle(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if handle is None:
            continue
        checked += 1
        if not _announces_itself(handle):
            missing.append(path.name)
    assert checked, "no management commands were found, so this guard would pass vacuously"
    assert not missing, (
        f"these commands do not log a WARNING naming the command and identity_tail(...) as they start: {missing}"
    )


def test_the_command_guard_can_see_a_command_that_does_not():
    silent = ast.parse("class Command:\n    def handle(self, *args, **options):\n        do_work()\n")
    assert not _announces_itself(_handle(silent))
