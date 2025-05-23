import logging
import threading

_log_locks = {}


def setup_logger(name, log_file=None, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s)"
        )
        if not logfile:
            logfile = f"{name.lower()}.log"
            
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        _log_locks[name] = threading.Lock()

    return logger


def safe_log(logger, msg, level="info"):
    lock = _log_locks.get(logger.name, threading.Lock())
    with lock:
        log_func = getattr(logger, level, logger.info)
        log_func(msg)
