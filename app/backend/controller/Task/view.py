from . import Task
from app.backend.controller.scan.core import Scan
from flask import json, render_template, request, jsonify, redirect, url_for
from flask import json, jsonify
from flask_login import current_user, login_required
from .task import Schedule



@Task.route('/task/add', methods=['POST'])

def add_job():
    '''新增作业'''
    # {'task_name': '123', 'task_desc': '222', 'task_target_ip': '123',
    #  'task_func': ['sv', 'vulscan', 'os', 'ping'], 'task_deps_db': ['cve'],
    # 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'],
    # 'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}
    response = {'status': '-1'}
    try:
        info = request.get_json(force=True)
        sc = Schedule(info=info)
        sc.add_task()
        task_id = sc.info["task_id"]
        response['status'] = 200
        response['msg'] = "job [%s] add success!"%task_id
        response['result'] = True
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)


@Task.route('/task/pause', methods=['POST'])
# @login_required
def pause_job():
    '''暂停作业'''
    # print(request)
    response = {'status': False}
    try:
        data = request.get_json(force=True)
        # print (data)
        job_id = data.get('id')
        # print(job_id)
        scheduler.pause_job(job_id)
        response['msg'] = "job[%s] pause success!" % job_id
        response['status'] = 200
    except Exception as e:
        response['msg'] = str(e)
    log_handler.add_log(request, LogActions.EDIT_SCAN, ActionResult.success, str(response))
    return jsonify(response)


@Task.route('/task/delete', methods=['POST'])
def test2():
    schedule = request.form.get('schedule')
    print(type(schedule))
    return 'hello'
