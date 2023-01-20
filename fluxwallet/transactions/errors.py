import logging

_logger = logging.getLogger(__name__)


class TransactionError(Exception):
    """
    Handle Transaction class Exceptions
    """

    def __init__(self, msg=""):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg
