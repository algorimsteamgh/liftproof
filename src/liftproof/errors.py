"""Exit codes and the exceptions that map to them (Technical Spec 13).

0   run completed, no differences found
10  run completed, differences found
2   run failed; the tool could not complete (not a verdict on the migration)
3   configuration or connection error; nothing was validated
1   reserved for an unexpected crash. The CLI maps any unhandled exception to 2, so a
    bare 1 can only come from the interpreter itself and is never read as a verdict.
"""

EXIT_OK = 0
EXIT_CRASH = 1
EXIT_RUN_FAILED = 2
EXIT_CONFIG = 3
EXIT_DIFFERENCES = 10


class LiftproofError(Exception):
    exit_code = EXIT_RUN_FAILED


class RunFailed(LiftproofError):
    """The run could not complete."""

    exit_code = EXIT_RUN_FAILED


class ConfigError(LiftproofError):
    """Configuration, credential or connection problem. Nothing was validated."""

    exit_code = EXIT_CONFIG
