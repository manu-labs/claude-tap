"""Pytest configuration for real E2E tests.

These tests require a working `claude` CLI installation and are skipped by default.
Use --run-real-e2e to enable them.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest


def pytest_addoption(parser):
    """Add --run-real-e2e command-line flag."""
    parser.addoption(
        "--run-real-e2e",
        action="store_true",
        default=False,
        help="Run real E2E tests that require a working claude CLI.",
    )


def pytest_collection_modifyitems(config, items):
    """Skip real E2E tests unless --run-real-e2e is passed."""
    if config.getoption("--run-real-e2e"):
        return
    skip_marker = pytest.mark.skip(reason="Need --run-real-e2e flag to run real E2E tests")
    e2e_dir = str(Path(__file__).parent)
    for item in items:
        if str(item.fspath).startswith(e2e_dir):
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def installed_claude_tap():
    """Verify claude-tap is importable from the current environment.

    The project should already be installed via `uv run` or `pip install -e .`.
    Returns the project root directory.
    """
    project_dir = Path(__file__).parent.parent.parent
    # Verify the package is importable (uv run handles installation)
    try:
        import claude_tap  # noqa: F401
    except ImportError:
        pytest.fail("claude_tap is not installed. Run with: uv run --extra dev pytest tests/e2e/ --run-real-e2e")
    return project_dir


@pytest.fixture
def claude_env(installed_claude_tap):
    """Run claude-tap as a wrapper around claude -p (normal usage mode).

    claude-tap launches claude as a child process and sets ANTHROPIC_BASE_URL
    internally. This fixture provides the trace_dir and a helper to run
    prompts through claude-tap.

    Note: Claude Code uses OAuth authentication which is bound to the official
    API endpoint. Setting ANTHROPIC_BASE_URL manually causes 403 errors.
    Instead, we use claude-tap's normal mode where it wraps the claude CLI
    and manages the env vars itself.
    """
    trace_dir = tempfile.mkdtemp(prefix="claude_tap_real_e2e_")

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    # Remove nesting detection vars
    env.pop("CLAUDECODE", None)
    env.pop("CLAUDE_CODE_SSE_PORT", None)
    # Disable update check in tests
    env["CLAUDE_TAP_PYPI_URL"] = "http://127.0.0.1:1/invalid"

    yield env, trace_dir

    # Keep trace dir on failure for debugging; clean on success
    # (pytest captures can be inspected)
    shutil.rmtree(trace_dir, ignore_errors=True)
