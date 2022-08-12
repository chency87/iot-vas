import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import firmware
from . import core
#已测试
@firmware.route('/firmware', methods=['GET'])
def view_firmware_detail():
    start = request.args.get('start')
    length = request.args.get('length')
    banner_text = request.args.get('search')
    try:
        return core.core_extract_banner(start, length, banner_text)
    except Exception as e:
        print(e)

@firmware.route('/firmware/risk', methods=['GET'])
def view_firmware():
    #需要根据firmware_hash获取返回RiskSummary和VulnerableComponent的信息
    #因此创建表FirmwareRiskSummaryVulnerableComponentRelation
    #获取firmware_hash
    firmware_hash = request.args.get('firmware_hash')
    try:
        return core.core_risk(firmware_hash)
    except Exception as e:
        print(e)
#已测试
@firmware.route('/firmware/accounts', methods=['GET'])
def view_firmware_accounts():
    firmware_hash = request.args.get('firmware_hash')
    return core.core_account(firmware_hash)

#已测试
@firmware.route('/firmware/private-keys', methods=['GET'])
def view_firmware_private_keys():
    firmware_hash = request.args.get('firmware_hash')
    try:
        return core.core_private_keys(firmware_hash)
    except Exception as e:
        print(e)
#已测试
@firmware.route('/firmware/weak-keys', methods=['GET'])
def view_firmware_weak_keys():
    firmware_hash = request.args.get('firmware_hash')
    return core.core_weak_keys(firmware_hash)

#已测试
@firmware.route('/firmware/expired-certs', methods=['GET'])
def view_firmware_expired_certs():
    firmware_hash = request.args.get('firmware_hash')
    try:
        return core.core_expired_certs(firmware_hash)
    except Exception as e:
        print(e)
#已测试
@firmware.route('/firmware/weak-certs', methods=['GET'])
def view_firmware_weak_certs():
    firmware_hash = request.args.get('firmware_hash')
    try:
        return core.core_weak_certs(firmware_hash)
    except Exception as e:
        print(e)

#已测试
@firmware.route('/firmware/config-issues', methods=['GET'])
def view_firmware_config_issues():
    firmware_hash = request.args.get('firmware_hash')
    try:
        return core.core_config_issues(firmware_hash)
    except Exception as e:
        print(e)


