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
    return core.core_extract_banner(start, length, banner_text)

@firmware.route('/firmware/risk', methods=['POST'])
def view_firmware():
    #需要根据firmware_hash获取返回RiskSummary和VulnerableComponent的信息
    #因此创建表FirmwareRiskSummaryVulnerableComponentRelation
    #获取firmware_hash
    firmware_hash = request.form['firmware_hash']
    return core.core_risk(firmware_hash)

#已测试
@firmware.route('/firmware/accounts', methods=['POST'])
def view_firmware_accounts():
    firmware_hash = request.form['firmware_hash']
    return core.core_accounts(firmware_hash)

#已测试
@firmware.route('/firmware/private-keys', methods=['POST'])
def view_firmware_private_keys():
    firmware_hash = request.form['firmware_hash']
    return core.core_private_keys(firmware_hash)

#已测试
@firmware.route('/firmware/weak-keys', methods=['POST'])
def view_firmware_weak_keys():
    firmware_hash = request.form['firmware_hash']
    return core.core_weak_keys(firmware_hash)

#已测试
@firmware.route('/firmware/expired-certs', methods=['POST'])
def view_firmware_expired_certs():
    firmware_hash = request.form['firmware_hash']
    return core.core_expired_certs(firmware_hash)

#已测试
@firmware.route('/firmware/weak-certs', methods=['POST'])
def view_firmware_weak_certs():
    firmware_hash = request.form['firmware_hash']
    return core.core_weak_certs(firmware_hash)

#已测试
@firmware.route('/firmware/config-issues', methods=['POST'])
def view_firmware_config_issues():
    firmware_hash = request.form['firmware_hash']
    return core.core_config_issues(firmware_hash)

@firmware.route('/firmware', methods=['GET'])
def view_firmware_list():
    return None

