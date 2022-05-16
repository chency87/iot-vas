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


@Task.route('/task/create', methods=['POST', "GET"])
def add_job():
    '''新增作业'''
    # {'task_name': '123', 'task_desc': '222', 'task_target_ip': '123',
    #  'task_func': ['sv', 'vulscan', 'os', 'ping'], 'task_deps_db': ['cve'],
    # 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'],
    # 'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}
    response = {'status': '-1'}
    info = dict(
        name="123",
        target="198.53.49.46",
        task_id="",
        port="1-1000",
        rate=10000,
        scan_type=["UDP_Scan"],
        config=["service", "banner"],
        scan_desc="",
        script=["snmp*"],
        schedule={"triggers": "date"}
    )
    # info = request.get_json(force=True)
    sc = Schedule(info)
    result = sc.add_task()
    return "success"

@Task.route('/task/pause', methods=['POST'])
def pause_job():
    '''暂停作业'''
    # print(request)
    response = {'status': False}
    try:
        info = request.get_json(force=True)
        job_id = info.get('task_id')
        # print(job_id)
        scheduler.pause_job(job_id)
        response['msg'] = "job[%s] pause success!" % job_id
        response['status'] = 200
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)

@Task.route('/task/view',methods=['GET','POST'])
def view_job():
    """
    分页查看任务
    """
    data = Schedule_History.query.all()





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