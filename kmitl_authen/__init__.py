"""Resilient captive-portal authenticator for the KMITL campus network."""

__version__ = "2.0.0"

# Exit codes. Anything non-zero is meant to be restarted by the supervisor
# (systemd / Docker / Task Scheduler), so the daemon can always choose to die
# instead of hanging forever.
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_CREDENTIALS = 3
EXIT_WATCHDOG = 70
