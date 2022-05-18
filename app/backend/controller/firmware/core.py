import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import firmware


def core_risk(firmware_hash):
    # 获取表FirmwareRiskSummaryVulnerableComponentRelation中的信息
    firmware_risk_summary_vulnerable_component_relation = dao.query_firmware_risk_summary_vulnerable_component_relation(
        None, firmware_hash)

    if (firmware_risk_summary_vulnerable_component_relation is None):
        return jsonify({"code": 404, "status": "error", "message": "没有查询到相关信息"})

    id_RiskSummary = firmware_risk_summary_vulnerable_component_relation.id_RiskSummary
    id_VulnerableComponent = firmware_risk_summary_vulnerable_component_relation.id_VulnerableComponent

    # 获取表RiskSummary中的信息
    risk_summary = dao.query_risk_summary(id_RiskSummary)

    net_services_risk = ""
    crypto_risk = ""
    kernel_risk = ""
    client_tools_risk = ""

    try:
        net_services_risk = risk_summary.net_services_risk
        crypto_risk = risk_summary.crypto_risk
        kernel_risk = risk_summary.kernel_risk
        client_tools_risk = risk_summary.client_tools_risk
    except Exception as e:
        print(e)

    # 获取表VulnerableComponent中的信
    vulnerable_component = dao.query_vulnerable_component(id_VulnerableComponent)

    name = ""
    version = ""
    category = ""
    vulnerabilities = ""
    cvss_max = ""

    try:
        name = vulnerable_component.name
        version = vulnerable_component.version
        category = vulnerable_component.category
        vulnerabilities = vulnerable_component.vulnerabilities
        cvss_max = vulnerable_component.cvss_max
    except Exception as e:
        print(e)

    # 返回数据
    return ({
        "code": 20000,
        "data": {
            "net_services_risk": net_services_risk,
            "crypto_risk": crypto_risk,
            "kernel_risk": kernel_risk,
            "client_tools_risk": client_tools_risk,
            "name": name,
            "version": version,
            "category": category,
            "vulnerabilities": vulnerabilities,
            "cvss_max": cvss_max
        }
    })


def core_account(firmware_hash):
    # class DefaultAccount(db.Model):
    #     __tablename__ = 'default_account'
    #     id = db.Column(db.Integer, primary_key=True)
    #     name = db.Column(db.String(512))
    #     pwd_hash = db.Column(db.String(512))
    #     hash_algorithm = db.Column(db.String(512))  # title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
    #     shell = db.Column(db.String(512))
    #     uid = db.Column(db.Integer)
    #     gid = db.Column(db.Integer)
    #     home_dir = db.Column(db.String(512))

    # class DefaultAccountRelationship(db.Model):
    #     __tablename__ = 'default_account_relationship'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_DefaultAccount = db.Column(db.Integer)  # Reference_key to DefaultAccount

    # 获取表DefaultAccountRelationship中的信息

    default_account_relationship = dao.query_default_account_relationship(None, None, firmware_hash)
    if (default_account_relationship is None):
        return ({
            "code": 404,
            "status": "error",
            "message": "没有查询到相关信息"
        })
    id_DefaultAccount = default_account_relationship.id_DefaultAccount
    if (id_DefaultAccount is None):
        return ({
            "code": 404,
            "status": "error",
            "message": "没有查询到相关信息"
        })

    # 获取表DefaultAccount中的信息

    name = ""
    pwd_hash = ""
    hash_algorithm = ""
    shell = ""
    uid = ""
    gid = ""
    home_dir = ""

    try:
        default_account = dao.query_default_account(id_DefaultAccount, None, None, None, None, None, None, None)
        name = default_account.name
        pwd_hash = default_account.pwd_hash
        hash_algorithm = default_account.hash_algorithm
        shell = default_account.shell
        uid = default_account.uid
        gid = default_account.gid
        home_dir = default_account.home_dir
    except Exception as e:
        print(e)

    # 返回数据
    return ({
        "code": 20000,
        "data": {
            "name": name,
            "pwd_hash": pwd_hash,
            "hash_algorithm": hash_algorithm,
            "shell": shell,
            "uid": uid,
            "gid": gid,
            "home_dir": home_dir
        }
    })


def core_private_keys(firmware_hash):
    # class CryptoKey(db.Model):
    #     __tablename__ = 'cryptokey'
    #     id = db.Column(db.Integer, primary_key=True)
    #     file_name = db.Column(db.String(512))
    #     file_hash = db.Column(db.String(512))
    #     pem_type = db.Column(db.String(512))
    #     algorithm = db.Column(db.String(512))
    #     bits = db.Column(db.Integer)

    # class CryptoKeyRelation(db.Model):
    #     __tablename__ = 'crypto_key_relation'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_CryptoKey = db.Column(db.Integer)  # Reference_key to CryptoKey

    # 获取表CryptoKeyRelationship中的信息
    crypto_key_relationship = dao.query_crypto_key_relation(None, None, firmware_hash)
    if (crypto_key_relationship is None):
        return "No Crypto Key Relationship"
    id_CryptoKey = crypto_key_relationship.id_CryptoKey

    # 获取表CryptoKey中的信息
    file_name = ""
    file_hash = ""
    pem_type = ""
    algorithm = ""
    bits = 0
    try:
        crypto_key = dao.query_crypto_key(id_CryptoKey, None, None, None, None, None)
        file_name = crypto_key.file_name
        file_hash = crypto_key.file_hash
        pem_type = crypto_key.pem_type
        algorithm = crypto_key.algorithm
        bits = crypto_key.bits
    except Exception as e:
        print(e)

    return ({
        "code": 20000,
        "data": {
            "file_name": file_name,
            "file_hash": file_hash,
            "pem_type": pem_type,
            "algorithm": algorithm,
            "bits": str(bits)
        }
    })


def core_weak_keys(firmware_hash):
    # class CryptoKey(db.Model):
    #     __tablename__ = 'cryptokey'
    #     id = db.Column(db.Integer, primary_key=True)
    #     file_name = db.Column(db.String(512))
    #     file_hash = db.Column(db.String(512))
    #     pem_type = db.Column(db.String(512))
    #     algorithm = db.Column(db.String(512))
    #     bits = db.Column(db.Integer)

    # class CryptoKeyRelation(db.Model):
    #     __tablename__ = 'crypto_key_relation'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_CryptoKey = db.Column(db.Integer)  # Reference_key to CryptoKey

    # 获取表CryptoKeyRelationship中的信息
    crypto_key_relationship = dao.query_crypto_key_relation(None, None, firmware_hash)
    if (crypto_key_relationship is None):
        return "No Crypto Key Relationship"

    id_CryptoKey = crypto_key_relationship.id_CryptoKey

    # 获取表CryptoKey中的信息
    file_name = ""
    file_hash = ""
    pem_type = ""
    algorithm = ""
    bits = 0
    try:
        crypto_key = dao.query_crypto_key(id_CryptoKey, None, None, None, None, None)
        file_name = crypto_key.file_name
        file_hash = crypto_key.file_hash
        pem_type = crypto_key.pem_type
        algorithm = crypto_key.algorithm
        bits = crypto_key.bits  # 过滤出较短的key
    except Exception as e:
        print(e)

    return ({
        "code": 20000,
        "data": {
            "file_name": file_name,
            "file_hash": file_hash,
            "pem_type": pem_type,
            "algorithm": algorithm,
            "bits": str(bits)
        }
    })


def core_expired_certs(firmware_hash):
    # class ExpiredCert(db.Model):
    #     __tablename__ = 'expired_cert'
    #     id = db.Column(db.Integer, primary_key=True)
    #     file_name = db.Column(db.String(512))
    #     file_hash = db.Column(db.String(512))
    #     thumb_print = db.Column(db.String(512))
    #     public_key = db.Column(db.Integer) # public key , refer to  PublicKey
    #     subject_name = db.Column(db.String(512))
    #     valid_form = db.Column(db.String(512))
    #     valid_to =  db.Column(db.String(512))

    # class ExpiredCertRelation(db.Model):
    #     __tablename__ = 'expired_cert_relation'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_ExpiredCert = db.Column(db.Integer)  # Reference_key to ExpiredCert
    #     firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    # 获取表ExpiredCertRelationship中的信息
    expired_cert_relationship = dao.query_expired_cert_relation(None, None, firmware_hash)
    if (expired_cert_relationship is None):
        return jsonify({
            "expired_certs": []
        })
    id_ExpiredCert = expired_cert_relationship.id_ExpiredCert

    # 获取表ExpiredCert中的信息
    file_name = ""
    file_hash = ""
    thumb_print = ""
    public_key = ""
    subject_name = ""
    valid_form = ""
    valid_to = ""
    try:
        expired_cert, public_key = dao.query_expired_cert(id_ExpiredCert, None, None, None, None, None, None, None,
                                                          None, None)
        file_name = expired_cert.file_name
        file_hash = expired_cert.file_hash
        thumb_print = expired_cert.thumb_print
        public_key = expired_cert.public_key
        subject_name = expired_cert.subject_name
        valid_form = expired_cert.valid_form
        valid_to = expired_cert.valid_to
    except Exception as e:
        print(e)

    return ({
        "code": 20000,
        "data": [{
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "public_key": public_key,
            "subject_name": subject_name,
            "valid_form": valid_form,
            "valid_to": valid_to
        }]
    })


def core_weak_certs(firmware_hash):
    # class WeakCert(db.Model):
    #     __tablename__ = 'weak_cert'
    #     id = db.Column(db.Integer, primary_key=True)
    #
    #     file_name = db.Column(db.String(512))
    #     file_hash = db.Column(db.String(512))
    #     thumb_print = db.Column(db.String(512))
    #     sign_algorithm = db.Column(db.String(512))
    #     subject_name = db.Column(db.String(512))
    #     valid_from = db.Column(db.String(512))
    #     valid_to = db.Column(db.String(512))

    # class WeakCertRelation(db.Model):
    #     __tablename__ = 'weak_cert_relation'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_WeakCert = db.Column(db.Integer)  # Reference_key to WeakCert
    #     firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    # 获取表WeakCertRelationship中的信息
    weak_cert_relationship = dao.query_weak_cert_relation(None, None, firmware_hash)

    if (weak_cert_relationship is None):
        return jsonify({
            "weak_certs": ""
        })

    id_WeakCert = weak_cert_relationship.id_WeakCert

    # 获取表WeakCert中的信息
    file_name = ""
    file_hash = ""
    thumb_print = ""
    sign_algorithm = ""
    subject_name = ""
    valid_from = ""
    valid_to = ""
    try:
        weak_cert = dao.query_weak_cert(id_WeakCert, None, None, None, None, None, None)
        file_name = weak_cert.file_name
        file_hash = weak_cert.file_hash
        thumb_print = weak_cert.thumb_print
        sign_algorithm = weak_cert.sign_algorithm
        subject_name = weak_cert.subject_name
        valid_from = weak_cert.valid_from
        valid_to = weak_cert.valid_to
    except Exception as e:
        print(e)

    return ({
        "code": 20000,
        "data": {
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "sign_algorithm": sign_algorithm,
            "subject_name": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to
        }
    })


def core_config_issues(firmware_hash):
    # class ConfigIssue(db.Model):
    #     __tablename__ = 'config_issue'
    #     id = db.Column(db.Integer, primary_key=True)
    #     service_name = db.Column(db.String(512))
    #     config_file = db.Column(db.String(512))
    #     issues = db.Column(db.String(512))  # List of detected issues
    #     suggestions = db.Column(db.String(512)) # List of suggestions to fix the issues

    # class ConfigIssueRelation(db.Model):
    #     __tablename__ = 'config_issue_relation'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_ConfigIssue = db.Column(db.Integer)  # Reference_key to ConfigIssue
    #     firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo
    # 获取表ConfigIssueRelationship中的信息
    config_issue_relationship = dao.query_config_issue_relation(None, None, firmware_hash)
    if (config_issue_relationship is None):
        return jsonify({
            "config_issues": []
        })

    id_ConfigIssue = config_issue_relationship.id_ConfigIssue

    # 获取表ConfigIssue中的信息
    service_name = ""
    config_file = ""
    issues = ""
    suggestions = ""
    try:
        config_issue = dao.query_config_issue(id_ConfigIssue, None, None, None, None)
        service_name = config_issue.service_name
        config_file = config_issue.config_file
        issues = config_issue.issues
        suggestions = config_issue.suggestions
    except Exception as e:
        print(e)

    return ({
        "code": 20000,
        "data": {
            "service_name": service_name,
            "config_file": config_file,
            "issues": issues,
            "suggestions": suggestions
        }
    })


def core_extract_banner(start, length, banner):
    data = {
        "data": [
            {
            "manufacturer": "11222",
             "model_name": "P3346",
             "firmware_version": "5.20",
             "is_discontinued": 'true',
             "cve_list":
                 [{"cve_id": "CVE-2018-10660", "cvss": 10},
                  {"cve_id": "CVE-2018-10662", "cvss": 10},
                  {"cve_id": "CVE-2018-10661", "cvss": 10},
                  {"cve_id": "CVE-2018-10658", "cvss": 5},
                  {"cve_id": "CVE-2018-10659", "cvss": 5},
                  {"cve_id": "CVE-2018-10663", "cvss": 5},
                  {"cve_id": "CVE-2018-10664", "cvss": 5}],
             "device_type": "IP Camera",
             "firmware_info":
            {
                "name": "AXIS P3346 5.20", "version": "5.20",
                "sha2": "af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175",
                "release_date": "2010-12-03",
                "download_url": "http://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_20/P3346_5_20.bin"},
                "latest_firmware_info":
            {
                     "name": "AXIS P3346 5.51.7.3", "version": "5.51.7.3",
                     "sha2": "a72361af68bd94f07cdf8b6c43389f4f382576bab752d4fb25dc74e93d4767a7",
                     "release_date": "2020-12-03",
                     "download_url": "https://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_51_7_3/P3346_5_51_7_3.bin"
            }
            },
            {
                "manufacturer": "Omron",
                "model_name": "PLC 3000",
                "firmware_version": "15.8",
                "device_type": "PLC",
                "is_discontinued": "True",
                "cve_list":
                    [
                        {"cve_id": 1, "cvss": 25},
                        {"cveId": 2, "cvss": 35}],
                "firmware_info":
                    [
                        {"name": "S7 - 1001", "version": "30.2", "sha2": "shabbuhuiasd2131b2u23", "release_date": "2022.02.01",
                  "download_url": "www.google.com"}],
             "latest_firmware_info":
                 {
                      "name": "S7 - 1001",
                      "version": "30.2",
                      "sha2": "shabbuhuiasd2131b2u23",
                      "release_date": "2022.02.01",
                      "download_url": "www.google.com"
                  }
            }
        ]
    }

    data_none = {
        "data": [
            {
            "manufacturer": None,
             "model_name": None,
             "firmware_version": None,
             "is_discontinued": None,
             "cve_list":None,
             "device_type": None,
             "firmware_info":None,
            "latest_firmware_info":None
            }
        ]
    }

    if banner is None or len(banner) == 0:
        return ({'code': 404, 'msg': 'banner is None'})
    dict1 = json.loads(banner)

    print(dict1)

    key = ""
    value = ""

    # 得到不空的key-value
    for i in dict1:
        if (dict1[i] != ""):
            key = i
            value = dict1[i]

    if (key == ""):
        print("key is None")
        return {'code': 20000, 'data': data_none}

    device_info1 = None

    snmp_sysdescr = ""
    snmp_sysoid = ""
    ftp_banner = ""
    telnet_banner = ""
    hostname = ""
    http_response = ""
    https_response = ""
    upnp_response = ""
    nic_mac = ""

    try:
        if (key == "snmp_sysdescr"):
            device_info1 = dao.query_all_device_features(None, str(value), None, None, None, None, None, None, None,
                                                         None)
        elif (key == "snmp_sysoid"):
            device_info1 = dao.query_all_device_features(None, None, str(value), None, None, None, None, None, None,
                                                         None)
        elif (key == "ftp_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, str(value), None, None, None, None, None,
                                                         None)
        elif (key == "telnet_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, None, str(value), None, None, None, None,
                                                         None)
        elif (key == "hostname"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, str(value), None, None, None,
                                                         None)
        elif (key == "http_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, str(value), None, None,
                                                         None)
        elif (key == "https_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, str(value), None,
                                                         None)
        elif (key == "upnp_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, str(value),
                                                         None)
        elif (key == "nic_mac"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, None,
                                                         str(value))
    except Exception as e:
        return {
            "code": 20000,
            "data": data_none
        }

    if (device_info1 is None):
        return {
            "code": 20000,
            "data": data_none
        }

    id = device_info1.id

    if (id is None):
        return {
            "code": 20000,
            "data": data_none
        }

    id_device_features = []
    for i in range(0, len(device_info1)):
        id_device_features.append(device_info1[i].id)

    data = []

    for i in range(0, len(id_device_features)):
        device_temp_info = dao.query_device_features_info_relation(None, id_device_features[i], None)
        id_device_info = device_temp_info.id_DeviceInfo
        id_device_features_info = device_temp_info.id_DeviceFeaturesInfo
        device_info = dao.query_device_infor(id_device_info,None,None,None,None,None)
        device_features = dao.query_device_features(id_device_features_info, None, None, None, None, None, None, None,
                                                    None, None)

        snmp_sysdescr = device_info.snmp_sysdescr
        snmp_sysoid = device_info.snmp_sysoid
        ftp_banner = device_info.ftp_banner
        telnet_banner = device_info.telnet_banner
        hostname = device_info.hostname
        http_response = device_info.http_response
        https_response = device_info.https_response
        upnp_response = device_info.upnp_response
        nic_mac = device_info.nic_mac
        manufacturer = device_features.manufacturer
        model_name = device_features.model_name
        firmware_version = device_features.firmware_version
        is_discontinued = device_features.is_discontinued
        cve_list = device_features.cve_list
        device_type = device_features.device_type
        firmware_info = device_features.firmware_info#id
        latest_firmware_info = device_features.latest_firmware_info

        dict = {
            "manufacturer": manufacturer,
             "model_name": model_name,
             "firmware_version": firmware_version,
             "is_discontinued": is_discontinued,
             "cve_list":None,
             "device_type": device_type,
             "firmware_info":
            {
                "name": "AXIS P3346 5.20",
                "version": "5.20",
                "sha2": "af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175",
                "release_date": "2010-12-03",
                "download_url": "http://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_20/P3346_5_20.bin"},
                "latest_firmware_info":
                 {
                     "name": "AXIS P3346 5.51.7.3", "version": "5.51.7.3",
                     "sha2": "a72361af68bd94f07cdf8b6c43389f4f382576bab752d4fb25dc74e93d4767a7",
                     "release_date": "2020-12-03",
                     "download_url": "https://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_51_7_3/P3346_5_51_7_3.bin"
                 }
        }
        data.append(dict)

    return ({'code': 20000, 'data': data})
