from marshmallow import fields
from werkzeug.wrappers import response
from . import schedule
from flask import json, render_template, request, jsonify

from flask_login import current_user, login_required

from app.backend.extensions import scheduler
from app.backend.schema.schemas import UserSchema
from crontab import CronTab
from app.backend.handlers.logger.core import log_handler, LogActions, ActionResult
from app.backend.handlers.plugins.core import get_all_scripts
from .core import TRIGGER_BY_CRON, TRIGGER_BY_INTERVAL, TRIGGER_BY_DATE, init_exec_job, get_current_jobs_list, \
    get_task_log_by_id, get_task_report_by_stdout, get_task_report_by_id
from .template import dashboard_top
from app.backend.handlers.settings.core import PortDictMana

import json


@schedule.route('/task/details', methods=['GET'])
def show_tasks():
    response = {}
    job_id = request.args.get('id')
    info_list = get_current_jobs_list(job_id)
    # print(info_list)
    response['status'] = 200
    response['data'] = info_list
    response['count'] = len(info_list)
    # result = json.dumps(response)
    return jsonify(response)


@schedule.route('/task/pause', methods=['POST'])
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


@schedule.route('/task/resume', methods=['POST'])
# @login_required
def resume_job():
    '''恢复作业'''
    response = {'status': False}
    try:
        data = request.get_json(force=True)
        job_id = data.get('id')
        scheduler.resume_job(job_id)
        response['msg'] = "job[%s] resume success!" % job_id
        response['status'] = 20
    except Exception as e:
        response['msg'] = str(e)
    log_handler.add_log(request, LogActions.EDIT_SCAN, ActionResult.success, str(response))
    return jsonify(response)


@schedule.route('/task/remove', methods=['DELETE'])
def remove_jobs():
    '''删除作业'''
    response = {'status': False}
    try:
        data = request.get_json(force=True)
        job_id = data.get('id')
        if job_id != 'all':
            scheduler.remove_job(job_id)
            response['msg'] = "job [%s] remove success!" % job_id
        else:
            scheduler.remove_all_jobs()
            response['msg'] = "job all remove success!"
        response['status'] = 200
    except Exception as e:
        response['msg'] = str(e)
    log_handler.add_log(request, LogActions.DEL_SCAN, ActionResult.success, str(response))
    return jsonify(response)


@schedule.route('/task/add', methods=['POST'])
@login_required
def add_job():
    '''新增作业'''
    # {'task_name': '123', 'task_desc': '222', 'task_target_ip': '123', 
    #  'task_func': ['sv', 'vulscan', 'os', 'ping'], 'task_deps_db': ['cve'], 
    # 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'], 
    # 'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}
    response = {'status': '-1'}
    try:
        data = request.get_json(force=True)
        job_id = init_exec_job(scheduler, **data)
        response['status'] = 200
        response['msg'] = "job [%s] add success!" % job_id
        response['result'] = True
    except Exception as e:
        response['msg'] = str(e)
        # print(e)
    # print(response)
    log_handler.add_log(request, LogActions.ADD_SCAN, ActionResult.success, str(response))
    return jsonify(response)


@schedule.route('/task/scan.html', methods=['GET'])
def show_task_page():
    data = UserSchema().dump(current_user)
    return render_template('pages/scan/index.html', title="监测任务管理", header="感知终端监测-任务管理", form=data)


# @schedule.route('/task/create.html', methods=['GET'])
# def show_task_create_page():
#     data = UserSchema().dump(current_user)
#     return render_template('pages/scan/create.html', title="创建监测任务", header="感知终端监测-任务创建", form = data)


@schedule.route('/task/createscan.html', methods=['GET'])
def show_task_create_page2():
    port_dict = PortDictMana.get_all_port_dict()
    # for item in port_dict:
    #     print(item.to_json())

    scripts = get_all_scripts()
    data = UserSchema().dump(current_user)
    return render_template('pages/scan/createscan.html', title="创建监测任务", header="感知终端监测-任务创建", form=data,
                           scripts=scripts, port_dict=port_dict)


@schedule.route('/task/report', methods=['GET'])
def show_task_report_page():
    task_id = request.args.get('task_id')
    # print(task_id)
    tasks = get_task_log_by_id(task_id)

    # print(tasks)
    data = UserSchema().dump(current_user)
    return render_template('pages/scan/report.html', title="Report", header="感知终端监测-报告查看", form=data, tasks=tasks)


@schedule.route('/task/reportdetails', methods=['GET'])
def get_report_details():
    report_id = request.args.get('id')

    top, host_dict, service_list, port_list_counter, most_common_port_list, scan_info = get_task_report_by_id(report_id)
    # print(service_list)
    response = {'status': True}
    response['data'] = top
    response['scaninfo'] = scan_info
    response['hosts'] = json.dumps(host_dict, indent=4)
    response['service'] = json.dumps(service_list, indent=4)
    response['ports'] = port_list_counter
    response['most_ports'] = most_common_port_list
    return jsonify(response)
