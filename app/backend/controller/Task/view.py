from . import Task
from app.backend.controller.scan.core import Scan
from flask import json, render_template, request, jsonify, redirect, url_for


@Task.route('/task/create', methods=['GET'])
def test():
    sc = Scan(ip='198.53.49.46', ports='161', scan_argument='-sU', script_name='snmp*')
    result = sc.scan()
    print(result)
    return jsonify(result)
