#!/usr/bin/env python3

"""Module that manages users using filters loggers"""
from typing import List, Tuple
import re
import logging
import os
import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Filter datum for user data management"""
    for field in fields:
        message = re.sub(r"{}=.*?{}".format(field, separator),
                         "{}={}{}".format(field, redaction, separator), message)
    return message

class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: Tuple[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filter sensitive information in log records"""
        original_msg = record.msg
        if isinstance(record.msg, str):
            record.msg = filter_datum(self.fields, self.REDACTION,
                                      record.msg, self.SEPARATOR)
        formatted_msg = super().format(record)
        record.msg = original_msg  # Reset to original message
        return formatted_msg

def get_logger() -> logging.Logger:
    """This function will help us get the logger"""
    logger = logging.getLogger("user_data")

    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger.addHandler(handler)

    # Disable propagation
    logger.propagate = False
    return logger

def get_db() -> mysql.connector.connection.MySQLConnection:
    """Get the database of the application"""
    connection = mysql.connector.connect(
            user=os.environ.get("PERSONAL_DATA_DB_USERNAME", "root"),
            host=os.environ.get("PERSONAL_DATA_DB_HOST", "localhost"),
            password=os.environ.get("PERSONAL_DATA_DB_PASSWORD", ""),
            database=os.environ.get("PERSONAL_DATA_DB_NAME", "my_db")
            )
    return connection

def main() -> None:
    """Main function for our python script"""
    db = get_db()

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    logger = get_logger()
    for row in cursor:
        string1 = "name={}; email={}; phone={}; ssn={}; password={}; "
        string2 = "ip={}; last_login={}; user_agent={};"
        string = (string1 + string2).format(*row)
        logger.info(string)

if __name__ == '__main__':
    main()
