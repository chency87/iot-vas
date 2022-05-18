from . import Task
from app.backend.controller.scan.core import Scan
from flask import json, render_template, request, jsonify, redirect, url_for
from flask import json, jsonify
from flask_login import current_user, login_required
from .task import Schedule
from app.backend.extensions import scheduler
from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db
from flask_pagination import Pagination
from app.backend.models.Task_data.curd import get_all_report


@Task.route('/task/create', methods=['POST', "GET"])
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
    return "success"


@Task.route('/task/state_change', methods=['POST', 'GET'])
def task_change():
    info = request.get_json(force=True)
    params = dict(
        task_id=info["taskID"],
        status=info["status"]
    )
    sc = Schedule(info=params)
    sc.state_change()
    return "success_change"


# @Task.route('/task/delete',methods=['POST','GET'])
# def delete():
#     info = request.get_json(force=True)
#     params = dict(
#         task_id=info['taskID'],
#         status=info['status']
#     )
#     sc = Schedule(info=params)
#     sc.delete_task()


@Task.route('/task', methods=['GET'])
def view_job(page=None):
    """
    分页查看任务
    """
    start = request.args.get('start')
    length = request.args.get('length')
    search = request.args.get('search')
    # print(info)
    # data_none = {
    #     "data": [
    #         {
    #             'name': '终端探测(82.102.188.9/24)',
    #             'config': 'app.backend.handlers.schedule.core:exec_namp_scan',
    #             'id': 'cron-489053f2861e4f91ae7245sfc78946a5',
    #             'createdAt': '2022-09-12 12:37:58',
    #             'status': 'Pause',
    #             'target': '82.102.188.9/24',
    #             'finished': '2022-09-12 12:37:59'
    #         }
    #     ]
    # }
    return jsonify(
        {"code": 20000, "data":  get_all_report(start, length,search)}
    )


#
#
# @Task.route('/task/resume', methods=['POST'])
# def resume_job():
#     '''
#     恢复作业
#     '''
#
#     response = {'status': False}
#     try:
#         info = request.get_json(force=True)
#         job_id = info.get("task_id")
#         scheduler.resume_job(job_id)
#         response['msg'] = "job[%s] resume success!" % job_id
#         response['status'] = 20
#     except Exception as e:
#         response['msg'] = str(e)
#     return jsonify(response)
#
#
# @Task.route('/task/remove', methods=['DELETE'])
# def remove_jobs():
#     '''删除作业'''
#     response = {'status': False}
#     try:
#         info = request.get_json(force=True)
#         job_id = info.get('id')
#         # 删除全部的job_id
#         if job_id != 'all':
#             scheduler.remove_job(job_id)
#             response['msg'] = "job [%s] remove success!" % job_id
#         else:
#             scheduler.remove_all_jobs()
#             response['msg'] = "job all remove success!"
#         response['status'] = 200
#     except Exception as e:
#         response['msg'] = str(e)
#     return jsonify(response)

# 为web而造
@Task.route('/task/delete', methods=['POST'])
def delete_job():
    return None


@Task.route('/task/status', methods=['GET'])
def task_status():
    return None


@Task.route('/task/status', methods=['PUT'])
def task_status1():
    return None


@Task.route('/task/report', methods=['GET'])
def task_report():
    return None
