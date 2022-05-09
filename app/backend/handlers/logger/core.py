from logging import error, log

from app.conf import config

import os
from app.backend.database.database import db

from app.backend.models.models import OpterationLog

from app.backend.schema.schemas import UserSchema
from datetime import datetime

from flask_login import current_user
class LogActions:
    ADD_USER = 'ADD_USER'
    EDIT_USER = 'EDIT_USER'
    DEL_USER = 'DEL_USER'
    LOG_IN = 'LOG_IN'
    LOG_OUT = 'LOG_OUT'
    EXECSCAN = 'EXECSCAN'
    ADD_SCAN = 'ADD_SCAN'
    DEL_SCAN = 'DEL_SCAN'
    EDIT_SCAN = 'EDIT_SCAN'
    EDIT_DICT = 'EDIT_DICT'
    CONF_SYSTEM = 'CONF_SYSTEM'

class ActionResult:
    success = 'SUCCESS'
    permission_deny = 'PERMISSION_DENY'
    failure = 'FAILURE'


class log_handler:
    # def add_log()
    def add_log(request, event, result, detail):
        username =   current_user.username if current_user else ''
        ip = request.environ['REMOTE_ADDR'] if request.environ.get('HTTP_X_FORWARDED_FOR') is None else request.environ['HTTP_X_FORWARDED_FOR']
        browser = request.headers.get('User-Agent')
      
        
        log = OpterationLog(opt_ip = ip, opt_user = username, opt_browser = browser, opt_event = str(event), opt_result = str(result), opt_time = datetime.now(), opt_detail = detail)
        # print(log.to_json())
        db.session.add(log)
        db.session.commit()
    def query_log(page, per_page):
        return OpterationLog.query.paginate(page = page, per_page = per_page, error_out = False)

    def query_log_by_time():
        pass

    def query_log_by_user():
        pass

    def query_log_by_events():
        pass

    def delete_log():
        pass