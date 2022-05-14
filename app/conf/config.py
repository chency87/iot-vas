import os
from datetime import timedelta
import os, logging

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from app.backend.handlers import jsonlogging as jsonlogger
# from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from datetime import datetime


basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "test.db")






# 修改数据库相关的用户名，密码，及数据库
#postgres://chunyu:chunyu@postgres.chunyu.svc.cluster.dsl:5432/tpc_di
# postgresql://chunyu:chunyu@localhost:5432/iot
# postgres://postgres:password@127.0.0.1:5432/DBname
SQLALCHEMY_DATABASE_URI = 'postgresql://chunyu@postgres.chunyu.svc.cluster.dsl:5432/iot'

SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456@localhost:5432/iot'
# 设置该路径为 中nmap 的script 文件夹中,建立一个文件夹，用于存储脚本


SECRET_KEY = 'secret key'

NMAP_SCRIPT_PATH = '/opt/homebrew/Cellar/nmap/7.92/share/nmap/scripts' 
UPLOAD_FOLDER = os.path.join(NMAP_SCRIPT_PATH, 'upload')
LOGGING_FOLDER = os.path.join(basedir,'statics/logs/task_scheduler.log')
SCAN_XML_REPORT_FOLDER = os.path.join(basedir, 'statics/uploads/report')

MAX_CONTENT_LENGTH = 4 * 1024 * 1024
PERMANENT_SESSION_LIFETIME = timedelta(minutes=10)




class ScanScriptConf():
    # SCRIPT_FOLDER =os.path.join( basedir,'statics/uploads/scripts')
    SCRIPT_FOLDER = UPLOAD_FOLDER


db = {
    'SQLALCHEMY_DATABASE_URI': SQLALCHEMY_DATABASE_URI,
    'username': 'username',
    'password':'password',
    'SQLALCHEMY_TRACK_MODIFICATIONS': True
}
# CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            # this doesn't use record.created, so it is slightly off
            # now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['timestamp'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname



# apscheduler 配置
class TaskConfig(object):
    JOBS = [ ]
    SCHEDULER_JOBSTORES = {
        'default': SQLAlchemyJobStore(url=SQLALCHEMY_DATABASE_URI)
    }
    SCHEDULER_EXECUTORS = {
        # 'default': {'type': 'threadpool', 'max_workers': 20}
    }
    SCHEDULER_JOB_DEFAULTS = {
        'coalesce': False,
        'max_instances': 20
    }
    SCHEDULER_API_ENABLED = False
    # 设置时区
    # SCHEDULER_TIMEZONE = 'Asia/Shanghai'

    jobstores={'sqlite': SQLAlchemyJobStore(url=SQLALCHEMY_DATABASE_URI)},
    job_defaults={'misfire_grace_time': 15*60},

    # 任务日志
    log = logging.getLogger('IoT Scan Task Execute')
    log.setLevel(logging.DEBUG)  # DEBUG

    logHandler = logging.StreamHandler()
    logHandler = logging.FileHandler(LOGGING_FOLDER)
    formatter = CustomJsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
    # formatter = jsonlogger.JsonFormatter()
    logHandler.setFormatter(formatter)
    log.addHandler(logHandler)

  