# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Shared exception types and process exit codes."""

# Process exit codes (aligned with the UDMI reference device "pubber").
EXIT_OK = 0  # Clean shutdown, e.g. SIGTERM/SIGINT.
EXIT_FATAL = 1  # Configuration error or unexpected crash: the supervisor should restart us.
EXIT_RESTART = 192  # Restart requested via UDMI `system.operation.mode = restart`.


class GatewayConfigError(Exception):
    """Raised for unrecoverable configuration problems (missing files, invalid settings)."""
