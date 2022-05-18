from app.backend.controller.Task.task import Schedule
from app.backend.controller.Task.task import Task
from app.backend.extensions import scheduler
from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db
from app.backend.models.Task_data.curd import get_all_report


def add_job():
    '''新增作业'''
    # {'task_name': '123', 'task_desc': '222', 'task_target_ip': '123',
    #  'task_func': ['sv', 'vulscan', 'os', 'ping'], 'task_deps_db': ['cve'],
    # 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'],
    # 'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}
    response = {'status': '-1'}
    info={
        "name":"123",
        "target": "198.53.49.46",
        "task_id":"",
        "port": "161",
        "rate": 10000,
        "scan_type": ["UDP_Scan", "TCP_Scan"],
        "config": ["service","banner"],
        "scan_desc": "",
        "script": ["snmp*"],
        "schedule": {"triggers":"date"}
        }
    # info = request.get_json(force=True)
    sc = Schedule(info)
    sc.add_new_task()
    while(True):
        pass
add_job()

# if start + length - 1 > len(data):
#     for i in range(start - 1, len(data) - start + 1):
#         print(data[i])

#
# start  = 1 11 21 31 41
# if start + 9 > total
# total = 30
#
# return_data = []
# start  =  1
# length = 10
#
# start = 1
