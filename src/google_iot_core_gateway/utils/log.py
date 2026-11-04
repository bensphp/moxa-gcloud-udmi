"""Logging setup.

Change log:
    02 Dec 2021: Disabled colored log feature; disabled log file to avoid filling the disk.
    04 Nov 2026: Removed the unused colorlog handler; logs go to stderr (journald under systemd).
"""

import logging

LOG_FORMAT = "%(asctime)s: %(levelname)s - %(module)s - %(message)s"
DATE_FORMAT = "[%Y-%m-%d %H:%M:%S]"


def setup_logger():
    """
    Set up the root logger.
    Returns:
        Logger with established formatter.
    """
    logging.basicConfig(level=logging.INFO, datefmt=DATE_FORMAT, format=LOG_FORMAT)
    return logging.getLogger()


def update_logger_verbose_level(logger, verbose_level):
    if verbose_level == '1':
        logger.setLevel(logging.WARN)
        logger.warning("Enabled Warning Mode")
    elif verbose_level == '2':
        logger.setLevel(logging.DEBUG)
        logger.info("Enabled Debug Mode")
    elif verbose_level == '3':
        logger.setLevel(logging.INFO)
        logger.info("Enabled Info Mode")
