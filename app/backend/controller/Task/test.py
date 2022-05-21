import datetime

import nmap
from app.backend.controller.Task.task import Schedule, exe_task
from app.backend.controller.Task.task import Task
from app.backend.extensions import scheduler
from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db
from app.backend.models.Task_data.curd import get_all_report, get_report_by_id, add_schedule_history
from app.backend.models.dao.dao import use_report


def add_job():
    '''新增作业'''
    # {'task_name': '123', 'task_desc': '222', 'task_target_ip': '123',
    #  'task_func': ['sv', 'vulscan', 'os', 'ping'], 'task_deps_db': ['cve'],
    # 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'],
    # 'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}
    response = {'status': '-1'}
    info = {
        "name": "1123",
        "desc": "",
        "target": "1.1.1.1",
        "port": "80",
        "trigger": "date",
        "rate": 10000,
        "config": [
            "banner"
        ],
        "vuldb": [],
        "script": []
    }
    # info = request.get_json(force=True)
    sc = Schedule(info)
    sc.add_new_task()
    while (True):
        pass


def delete():
    task_id = 'date-0d89b8eaa2734878adb3958b4896252a'
    status = 'running'
    params = dict(
        task_id=task_id,
        status=status
    )
    sc = Schedule(info=params)
    sc.delete_task()
    print("success")
    return "success"



params = {"name": "脆弱性测试", "desc": "", "target": "195.145.172.34", "port": "443", "trigger": "date",
          "scan_type": ["TCP_Scan"], "rate": 100, "config": ["vul", "service"], "vuldb": [], "script": ["s7-info"]}
id = 'date-5e11b81ddacd41ceb3efd6f8a0133072'
exe_task(params=params, id=id)
while True:
    pass
