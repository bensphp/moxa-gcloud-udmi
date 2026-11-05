# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Process runner shared by main.py and `python -m google_iot_core_gateway`.

The gateway runs in a worker thread with SIGINT/SIGTERM blocked; the threads it starts (paho's
network loops, ...) inherit that mask. The main thread only waits and turns a stop signal into a
clean shutdown. A stop signal therefore never interrupts a system call of the gateway itself,
whenever it arrives (some calls, e.g. listen() or scandir(), are not retried by Python on EINTR).

Exit codes: 0 = clean shutdown, 1 = fatal error or crash, 192 = UDMI restart request.
"""

import signal
import threading

from google_iot_core_gateway.errors import EXIT_FATAL

STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)
SHUTDOWN_GRACE_SEC = 15.0  # below the systemd unit's TimeoutStopSec=20


def run_gateway_process(logger, run, stop_event, grace_sec=SHUTDOWN_GRACE_SEC) -> int:
    """Run `run()` (returns an exit code) in a worker thread until it ends or a stop signal arrives.

    Must be called from the main thread, which installs the SIGINT/SIGTERM handlers.
    """
    result = {"exit_code": EXIT_FATAL}

    def _handle_signal(signum, _frame):
        logger.info(f"Received signal {signum}; shutting down gateway...")
        stop_event.set()

    for signum in STOP_SIGNALS:
        signal.signal(signum, _handle_signal)

    def _worker():
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
        try:
            result["exit_code"] = run()
        except SystemExit as exc:
            result["exit_code"] = exc.code if isinstance(exc.code, int) else EXIT_FATAL
        except BaseException:  # noqa: BLE001 - report any crash through the exit code
            logger.exception("Gateway thread crashed")
            result["exit_code"] = EXIT_FATAL

    worker = threading.Thread(target=_worker, name="gateway", daemon=True)
    worker.start()
    while worker.is_alive() and not stop_event.is_set():
        worker.join(timeout=0.5)
    if worker.is_alive():
        # Shutdown requested: give the worker time to disconnect cleanly.
        worker.join(timeout=grace_sec)
        if worker.is_alive():
            logger.error("Gateway did not stop within %.0f s; exiting anyway", grace_sec)
            return EXIT_FATAL
    return result["exit_code"]
