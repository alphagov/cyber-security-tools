""" Declare a logger to be used by any module """
import datetime
import json
import logging
import os
import sys


class JsonFormatter(logging.Formatter):
    """ Handle log invokes with string, dict or json.dumps """

    def format(record: logging.LogRecord) -> str:  # type: ignore
        """
        Detect formatting of self message and encode as valid JSON

        According to the docs this method should have a record: LogRecord
        argument. It should be specifying self as the first argument to
        a class instance method but if you pass self then 2 things happen

        1. It doesn't work because the record argument is not passed at runtime
        2. The thing which has a .msg property becomes self but the Formatter
        super-class doesn't have a msg property. The thing with a msg propery
        is a LogRecord.

        This works round the issue so that the argument is of the right type
        but doesn't match Python OO syntax or the super class method signature
        """
        data = {}
        data.update(vars(record))
        try:
            # It seems that this self is actually an instance of LogRecord
            # but if I declare the function as a classmethod it doesn't work
            parsed = json.loads(record.msg)
            if type(parsed) in [dict, list]:
                data["msg"] = parsed
        except (ValueError, TypeError, json.JSONDecodeError):
            pass

        try:
            if ("args" in data) and len(data["args"]) > 0:
                args = data["args"]
                data["msg"] = data["msg"] % args
        except TypeError:
            pass

        data["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        try:
            log_message = json.dumps(data, default=str)
        except (TypeError, ValueError) as err:
            log_message = "logger_error=" + str(err) + ";event=" + str(data)
        return log_message


def build_logger(log_name: str, log_level: str = "ERROR") -> logging.Logger:
    """ Create shared logger and custom JSON handler """
    logger = logging.getLogger(log_name)
    handler = logging.StreamHandler(sys.stdout)
    # For some reason mypy doesn't understand sub-classes
    handler.setFormatter(JsonFormatter)  # type: ignore
    logger.handlers = []
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, log_level))
    return logger


LOG_LEVEL = str(os.getenv("LOG_LEVEL", "ERROR"))
if not LOG_LEVEL:
    # Handle LOG_LEVEL set to empty string
    # This happens if not declared in parent shell of docker-compose
    LOG_LEVEL = "ERROR"
LOG: logging.Logger = build_logger("json_logger", log_level=LOG_LEVEL)
