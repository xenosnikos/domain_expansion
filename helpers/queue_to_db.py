from datetime import datetime
from helpers import common_strings
from helpers.mongo_connection import db


def expansion_response_db_addition(value, output, filter_by_ip=False):
    db.expansion.find_one_and_update({common_strings.strings['mongo_value']: value,
                                      common_strings.strings['format_by_ip']: filter_by_ip},
                                     {'$set': {'status': common_strings.strings['status_finished'],
                                               'timeStamp': datetime.utcnow(), 'output': output}})
