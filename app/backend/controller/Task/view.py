from . import Task
from app.backend.controller.scan.core import Scan
from flask import json, render_template, request, jsonify, redirect, url_for
from flask import json, jsonify

@Task.route('/create/task', methods=['GET','POST'])
def test():
    info = {"name": "test", "desc": "desc", "target": "198.53.49.46", "port": "1-1000", "rate": 10000,
            "scan_type": ["TCP_Scan", "UDP_Scan"],
            "config": ["open_port", "service"], "vuldb": ["xforce", "vuldb", "openvas", "cve"],
            "script": ["snmp-interfaces", "snmp-sysdescr"]}
    task = Task(info=info)
    result = task.create_task()
    print('hello')
    return jsonify(result)
