from . import Task
from flask import json, render_template, request, jsonify, redirect, url_for
from flask import json, jsonify
from .task import Schedule
from app.backend.models.Task_data.curd import get_all_report
from app.backend.models.Task_data.curd import get_report_by_id


# 成功
@Task.route('/task', methods=['GET'])
def view_job():
    """
    分页查看任务
    """
    start = request.args.get('start')
    length = request.args.get('length')
    search = request.args.get('search')
    # print(info)
    return jsonify(
        {"code": 20000, "data": get_all_report(start, length, search)}
    )


# 成功
@Task.route('/task/create', methods=['POST'])
def add_job():
    '''新增作业'''
    info = request.get_json(force=True)
    print(info)
    sc = Schedule(info)
    sc.add_new_task()
    return jsonify(
        {"code": 20000, "data": "success"}
    )


# 成功
@Task.route('/task/delete', methods=['POST'])
def delete():
    task_id = request.get_json(force=True)
    print(task_id)
    params = dict(
        task_id=task_id,
        status='running'
    )
    print(params)
    sc = Schedule(info=params)
    sc.delete_task()
    return jsonify({"code": 20000, "data": {"status": "success"}})


@Task.route('/task/scanreport', methods=['GET'])
def view_report():
    print('hello')
    task_id = request.args.get('task_id')
    data = get_report_by_id(task_id=task_id)
    return jsonify(
        {"code": 20000, "data": data}
    )


# 成功
@Task.route('/task/status', methods=['PUT'])
def change_stauts():
    info = {}
    result = request.get_json(force=True)
    for k, v in result.items():
        id = k
        status = v
        info = dict(
            task_id=id,
            status=status
        )
    sc = Schedule(info=info)
    data = sc.status_change()
    return jsonify(
        {"code": 20000, "data": data}
    )

# @Task.route('/task/status',methods=['PUT'])
# def update_status():
#
