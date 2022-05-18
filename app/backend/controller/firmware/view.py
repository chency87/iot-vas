import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import firmware
from . import core
#已测试
@firmware.route('/firmware', methods=['GET'])
def view_firmware_detail():
    data = {"total":0.2,"data":[{"manufacturer":"11111","model_name":"P3346","firmware_version":"5.20","is_discontinued":'true',"cve_list":[{"cve_id":"CVE-2018-10660","cvss":10},{"cve_id":"CVE-2018-10662","cvss":10},{"cve_id":"CVE-2018-10661","cvss":10},{"cve_id":"CVE-2018-10658","cvss":5},{"cve_id":"CVE-2018-10659","cvss":5},{"cve_id":"CVE-2018-10663","cvss":5},{"cve_id":"CVE-2018-10664","cvss":5}],"device_type":"IP Camera","firmware_info":{"name":"AXIS P3346 5.20","version":"5.20","sha2":"af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175","release_date":"2010-12-03","download_url":"http://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_20/P3346_5_20.bin"},"latest_firmware_info":{"name":"AXIS P3346 5.51.7.3","version":"5.51.7.3","sha2":"a72361af68bd94f07cdf8b6c43389f4f382576bab752d4fb25dc74e93d4767a7","release_date":"2020-12-03","download_url":"https://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_51_7_3/P3346_5_51_7_3.bin"}},{"manufacturer":"Omron","model_name":"PLC 3000","firmware_version":"15.8","device_type":"PLC","is_discontinued":"True","cve_list":[{"cve_id":1,"cvss":25},{"cveId":2,"cvss":35}],"firmware_info":[{"name":"S7 - 1001","version":"30.2","sha2":"shabbuhuiasd2131b2u23","release_date":"2022.02.01","download_url":"www.google.com"}],"latest_firmware_info":{"name":"S7 - 1001","version":"30.2","sha2":"shabbuhuiasd2131b2u23","release_date":"2022.02.01","download_url":"www.google.com"}}]}

    return jsonify(
        {"code": 20000, "data": data}
    )

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

