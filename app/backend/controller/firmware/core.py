import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import firmware

# def core_risk(firmware_hash):
#     # 获取表FirmwareRiskSummaryVulnerableComponentRelation中的信息
#     firmware_risk_summary_vulnerable_component_relation = dao.query_firmware_risk_summary_vulnerable_component_relation(
#         None, firmware_hash)
#
#     if (firmware_risk_summary_vulnerable_component_relation is None):
#         return jsonify({"code": 404, "status": "error", "message": "没有查询到相关信息"})
#
#     id_RiskSummary = firmware_risk_summary_vulnerable_component_relation.id_RiskSummary
#     id_VulnerableComponent = firmware_risk_summary_vulnerable_component_relation.id_VulnerableComponent
#
#     # 获取表RiskSummary中的信息
#     risk_summary = dao.query_risk_summary(id_RiskSummary)
#
#     net_services_risk = ""
#     crypto_risk = ""
#     kernel_risk = ""
#     client_tools_risk = ""
#
#     try:
#         net_services_risk = risk_summary.net_services_risk
#         crypto_risk = risk_summary.crypto_risk
#         kernel_risk = risk_summary.kernel_risk
#         client_tools_risk = risk_summary.client_tools_risk
#     except Exception as e:
#         print(e)
#
#     # 获取表VulnerableComponent中的信
#     vulnerable_component = dao.query_vulnerable_component(id_VulnerableComponent)
#
#     name = ""
#     version = ""
#     category = ""
#     vulnerabilities = ""
#     cvss_max = ""
#
#     try:
#         name = vulnerable_component.name
#         version = vulnerable_component.version
#         category = vulnerable_component.category
#         vulnerabilities = vulnerable_component.vulnerabilities
#         cvss_max = vulnerable_component.cvss_max
#     except Exception as e:
#         print(e)
#
#     # 返回数据
#     return ({
#         "code": 20000,
#         "data": {
#             "net_services_risk": net_services_risk,
#             "crypto_risk": crypto_risk,
#             "kernel_risk": kernel_risk,
#             "client_tools_risk": client_tools_risk,
#             "name": name,
#             "version": version,
#             "category": category,
#             "vulnerabilities": vulnerabilities,
#             "cvss_max": cvss_max
#         }
#     })
from ...models.firmware_models import DeviceInfo


def core_risk(firmware_hash):
    # data_temp ={
    #   'risk_summary': {
    #     'net_services_risk': 'Critical',
    #     'crypto_risk': 'Critical',
    #     'kernel_risk': 'None',
    #     'client_tools_risk': 'High'
    #   },
    #   'vulnerable_components': [
    #     {
    #       'name': 'libupnp',
    #       'version': '1.4.1',
    #       'category': 'UPnP Server',
    #       'vulnerabilities': [
    #         {
    #           'cve_id': 'CVE-2012-5958',
    #           'cvss': 10
    #         },
    #         {
    #           'cve_id': 'CVE-2016-8863',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2020-13848',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2016-6255',
    #           'cvss': 5
    #         }
    #       ],
    #       'cvss_max': 10
    #     },
    #     {
    #       'name': 'openssl',
    #       'version': '0.9.7m',
    #       'category': 'Crypto Library',
    #       'vulnerabilities': [
    #         {
    #           'cve_id': 'CVE-2009-3245',
    #           'cvss': 10
    #         },
    #         {
    #           'cve_id': 'CVE-2016-2108',
    #           'cvss': 10
    #         },
    #         {
    #           'cve_id': 'CVE-2016-2109',
    #           'cvss': 7.8
    #         },
    #         {
    #           'cve_id': 'CVE-2010-0742',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2010-4252',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2012-2110',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-8176',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2015-0292',
    #           'cvss': 7.5
    #         },
    #         {
    #           'cve_id': 'CVE-2011-4354',
    #           'cvss': 5.8
    #         },
    #         {
    #           'cve_id': 'CVE-2008-5077',
    #           'cvss': 5.8
    #         },
    #         {
    #           'cve_id': 'CVE-2009-1387',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2006-7250',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2009-0789',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2009-1377',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2009-1378',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2009-4355',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2011-1473',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2011-4576',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2012-1165',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-3570',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-3571',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-3572',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-8275',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2015-0286',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2015-0287',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2015-1792',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2016-2106',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2009-1386',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2013-0166',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2017-3735',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2015-4000',
    #           'cvss': 4.3
    #         },
    #         {
    #           'cve_id': 'CVE-2014-0221',
    #           'cvss': 4.3
    #         },
    #         {
    #           'cve_id': 'CVE-2014-3470',
    #           'cvss': 4.3
    #         },
    #         {
    #           'cve_id': 'CVE-2016-0703',
    #           'cvss': 4.3
    #         },
    #         {
    #           'cve_id': 'CVE-2016-0704',
    #           'cvss': 4.3
    #         },
    #         {
    #           'cve_id': 'CVE-2010-5298',
    #           'cvss': 4
    #         },
    #         {
    #           'cve_id': 'CVE-2016-2107',
    #           'cvss': 2.6
    #         },
    #         {
    #           'cve_id': 'CVE-2011-1945',
    #           'cvss': 2.6
    #         },
    #         {
    #           'cve_id': 'CVE-2007-3108',
    #           'cvss': 1.2
    #         }
    #       ],
    #       'cvss_max': 10
    #     },
    #     {
    #       'name': 'busybox',
    #       'version': '1.1.3',
    #       'category': 'Client Tool',
    #       'vulnerabilities': [
    #         {
    #           'cve_id': 'CVE-2016-6301',
    #           'cvss': 7.8
    #         },
    #         {
    #           'cve_id': 'CVE-2011-2716',
    #           'cvss': 6.8
    #         },
    #         {
    #           'cve_id': 'CVE-2018-1000500',
    #           'cvss': 6.8
    #         },
    #         {
    #           'cve_id': 'CVE-2017-16544',
    #           'cvss': 6.5
    #         },
    #         {
    #           'cve_id': 'CVE-2011-5325',
    #           'cvss': 5
    #         },
    #         {
    #           'cve_id': 'CVE-2014-9645',
    #           'cvss': 2.1
    #         }
    #       ],
    #       'cvss_max': 7.8
    #     },
    #     {
    #       'name': 'dbus',
    #       'version': '1.2.4',
    #       'category': 'Generic Server',
    #       'vulnerabilities': [
    #         {
    #           'cve_id': 'CVE-2011-2533',
    #           'cvss': 3.3
    #         }
    #       ],
    #       'cvss_max': 3.3
    #     }
    #   ]
    # }
    # data_temp2 = {
    #     "data":data_temp
    # }
    # return jsonify(
    #     {
    #         "code": 20000,
    #         "data":data_temp2
    #     }
    # )

    data_none ={
      'risk_summary': {
        'net_services_risk': 'None',
        'crypto_risk': 'Normal',
        'kernel_risk': 'None',
        'client_tools_risk': 'None'
      },
        'vulnerable_components':
        [None]
    }

    # 获取表FirmwareRiskSummaryVulnerableComponentRelation中的信息
    firmware_risk_summary_vulnerable_component_relation = dao.query_all_firmware_risk_summary_vulnerable_component_relation(
        None, None, firmware_hash)

    if (firmware_risk_summary_vulnerable_component_relation is None or len(firmware_risk_summary_vulnerable_component_relation) == 0):
        return jsonify(
            {
                "code": 20000,
                "data":
                    {
                        "data": data_none
                    }
            }
        )

    for firmware_risk_summary_vulnerable_component_relation_item in firmware_risk_summary_vulnerable_component_relation:
        id_RiskSummary = firmware_risk_summary_vulnerable_component_relation_item.id_RiskSummary
        risk_summary = dao.query_risk_summary(id_RiskSummary)
        if(risk_summary is None):
            continue
        vulnerable_component = dao.query_vulnerable_component(id_RiskSummary)
        if(vulnerable_component is None):
            continue
        net_services_risk = risk_summary.net_services_risk
        crypto_risk = risk_summary.crypto_risk
        kernel_risk = risk_summary.kernel_risk
        client_tools_risk = risk_summary.client_tools_risk
        dict_risk_summary = {
            'net_services_risk': net_services_risk,
            'crypto_risk': crypto_risk,
            'kernel_risk': kernel_risk,
            'client_tools_risk': client_tools_risk
        }

        name = vulnerable_component.name
        version = vulnerable_component.version
        category = vulnerable_component.category
        vulnerabilities = vulnerable_component.vulnerabilities
        cvss_max = vulnerable_component.cvss_max

        ids = []
        dict_vulnerabilities = []

        list_vulnerabilities = vulnerabilities.split(',')
        for i in range(len(list_vulnerabilities)):
            ids.append(list_vulnerabilities[i])
        for i in range(len(ids)):
            vulnerabilities_i = dao.query_vulnerability(ids[i])
            dict_vulnerabilities.append({
                "cve_id": vulnerabilities_i.cve_id,
                "cvss": vulnerabilities_i.cvss
            })
        dict_vulnerable_components = []
        dict_vulnerable_components.append({
            "name": name,
            "version": version,
            "category": category,
            "vulnerabilities": dict_vulnerabilities,
            "cvss_max": cvss_max
        })
        newdata = {
            "data":
                {
                    "risk_summary": dict_risk_summary,
                    "vulnerable_components": dict_vulnerable_components
                }
        }
        # 返回数据
        print(newdata)
        return ({'code': 20000, 'data': newdata})

    return jsonify(
        {
            "code": 20000,
            "data":
                {
                    "data": data_none
                }
        }
    )

def core_account(firmware_hash):
    # accounts = [
    #     {
    #         'name': 'sessioncgi',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 127,
    #         'gid': 127,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'environment',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 132,
    #         'gid': 132,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'mediaclipcgi',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 134,
    #         'gid': 254,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'wsdd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 136,
    #         'gid': 136,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'triggerd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 120,
    #         'gid': 120,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'tampering',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 122,
    #         'gid': 122,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'storage',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 123,
    #         'gid': 123,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'focus',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 124,
    #         'gid': 124,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'wsd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 137,
    #         'gid': 137,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'capbufd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 138,
    #         'gid': 138,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'bin',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/sh',
    #         'uid': 1,
    #         'gid': 1,
    #         'home_dir': '/bin'
    #     },
    #     {
    #         'name': 'root',
    #         'pwd_hash': 'AiADGkJIfIlXk',
    #         'hash_algorithm': '0',
    #         'shell': '/bin/sh',
    #         'uid': 0,
    #         'gid': 0,
    #         'home_dir': '/root'
    #     },
    #     {
    #         'name': 'anonymous',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 57,
    #         'gid': 57,
    #         'home_dir': '/var/empty/'
    #     },
    #     {
    #         'name': 'daemon',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/sh',
    #         'uid': 2,
    #         'gid': 2,
    #         'home_dir': '/usr/sbin'
    #     },
    #     {
    #         'name': 'bw',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 102,
    #         'gid': 102,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'messagebus',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 101,
    #         'gid': 101,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'event',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 104,
    #         'gid': 104,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'motion',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 103,
    #         'gid': 103,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'axisns',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 106,
    #         'gid': 106,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'streamer',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 105,
    #         'gid': 105,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'iod',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 109,
    #         'gid': 109,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'mld',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 108,
    #         'gid': 108,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'ptzadm',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 113,
    #         'gid': 113,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'lang_handler',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 110,
    #         'gid': 110,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'upnp',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 115,
    #         'gid': 115,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'gtourd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 114,
    #         'gid': 114,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'stunnel',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 117,
    #         'gid': 117,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'rendezvous',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 116,
    #         'gid': 116,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'acd',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 119,
    #         'gid': 119,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'imaged',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 118,
    #         'gid': 118,
    #         'home_dir': '/'
    #     },
    #     {
    #         'name': 'nobody',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 254,
    #         'gid': 254,
    #         'home_dir': '/var/empty'
    #     },
    #     {
    #         'name': 'certcgi',
    #         'pwd_hash': '*',
    #         'hash_algorithm': 'null',
    #         'shell': '/bin/false',
    #         'uid': 142,
    #         'gid': 142,
    #         'home_dir': '/'
    #     }
    # ]
    # data_test = {
    #     "data": accounts
    # }
    # return (
    #     {
    #         "code": 20000,
    #         "data": data_test
    #     }
    # )

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
    data_none = {
        "data": [
            {
                "name": None,
                "pwd_hash": None,
                "hash_algorithm": None,
                "shell": None,
                "uid": None,
                "gid": None,
                "home_dir": None
            }
        ]
    }

    default_account_relationship = dao.query_all_default_account_relationship(None, None, firmware_hash)

    if (default_account_relationship is None or len(default_account_relationship) == 0):
        return ({
            "code": 20000,
            "data": data_none
        })
    id_DefaultAccount = []
    for default_account_relationship_item in default_account_relationship:
        id_DefaultAccount.append(default_account_relationship_item.id_DefaultAccount)
    if (id_DefaultAccount is None or len(id_DefaultAccount) == 0):
        return ({
            "code": 20000,
            "data": data_none
        })

    data_test_list = []
    for id_DefaultAccount_item in id_DefaultAccount:
        # 获取表DefaultAccount中的信息
        default_account = dao.query_default_account(id_DefaultAccount_item, None, None, None, None, None, None, None)
        name = default_account.name
        pwd_hash = default_account.pwd_hash
        hash_algorithm = default_account.hash_algorithm
        shell = default_account.shell
        uid = default_account.uid
        gid = default_account.gid
        home_dir = default_account.home_dir

        data_test = {
            "name": name,
            "pwd_hash": pwd_hash,
            "hash_algorithm": hash_algorithm,
            "shell": shell,
            "uid": uid,
            "gid": gid,
            "home_dir": home_dir
        }
        data_test_list.append(data_test)

    return (
        {
            "code": 20000,
            "data": {"data": data_test_list}
        }
    )


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
    data_none = {
        "data": [
            {
                'file_name': None,
                'file_hash': None,
                'pem_type': None,
                "algorithm": None,
                "bits": None
            }
        ]
    }

    # 获取表CryptoKeyRelationship中的信息
    crypto_key_relationship = dao.query_all_crypto_key_relation(None, None, firmware_hash)

    if (crypto_key_relationship is None or len(crypto_key_relationship) == 0):
        return ({"code": 20000, "data": data_none})

    id_CryptoKey = []
    for crypto_key_relationship_item in crypto_key_relationship:
        id_CryptoKey.append(crypto_key_relationship_item.id_CryptoKey)

    if (id_CryptoKey is None or len(id_CryptoKey) == 0):
        return ({"code": 20000, "data": data_none})

    # 获取表CryptoKey中的信息
    data_test_list = []
    for id_CryptoKey_item in id_CryptoKey:
        crypto_key = dao.query_crypto_key(id_CryptoKey_item, None, None, None, None, None)
        if(crypto_key is None):
            continue
        file_name = crypto_key.file_name
        file_hash = crypto_key.file_hash
        pem_type = crypto_key.pem_type
        algorithm = crypto_key.algorithm
        bits = crypto_key.bits

        data_test = {
            "file_name": file_name,
            "file_hash": file_hash,
            "pem_type": pem_type,
            "algorithm": algorithm,
            "bits": bits
        }
        data_test_list.append(data_test)

    return ({
        "code": 20000,
        "data": {"data": data_test_list }
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
    data_none = {
        "data": [
            {
                'file_name': None,
                'file_hash': None,
                'pem_type': None,
                "algorithm": None,
                "bits": None
            }
        ]
    }

    # 获取表CryptoKeyRelationship中的信息
    crypto_key_relationship = dao.query_crypto_key_relation(None, None, firmware_hash)
    if (crypto_key_relationship is None):
        return ({"code": 20000, "data": data_none})

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

    newdata = {
        "data": [
            {
                'file_name': file_name,
                'file_hash': file_hash,
                'pem_type': pem_type,
                'algorithm': algorithm,
                'bits': str(bits)
            }
        ]
    }
    return ({
        "code": 20000,
        "data": newdata
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

    data_none = {
        "data": [
            {
                'file_name': None,
                'file_hash': None,
                'thumb_print': None,
                'public_key': None,
                'subject_name': None,
                'valid_from': None,
                'valid_to': None,
            }
        ]
    }
    # 获取表ExpiredCertRelationship中的信息
    expired_cert_relationship = dao.query_all_expired_cert_relation(None, None, firmware_hash)

    if (expired_cert_relationship is None or len(expired_cert_relationship) == 0):
        return jsonify({
            "code": 20000, "data": data_none
        })
    id_ExpiredCert = []
    for expired_cert_relationship_item in expired_cert_relationship:
        id_ExpiredCert.append(expired_cert_relationship_item.id_ExpiredCert)

    test_list = []
    for id_ExpiredCert_item in id_ExpiredCert:
        expired_cert = dao.query_expired_cert(id_ExpiredCert_item, None, None, None, None, None, None, None,
                                                      None, None)
        if(expired_cert is None):
            continue
        file_name = expired_cert.file_name
        file_hash = expired_cert.file_hash
        thumb_print = expired_cert.thumb_print
        public_key = expired_cert.public_key
        subject_name = expired_cert.subject_name
        valid_from = expired_cert.valid_form
        valid_to = expired_cert.valid_to

        public_key_data = dao.query_public_key(public_key)
        algorithm = public_key_data.algorithm if public_key_data is not None else None
        bits = public_key_data.bits if public_key_data is not None else None
        data_test = {
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "public_key": {
                "algorithm": algorithm,
                "bits": bits
            },
            "subject_name": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to
        }
        test_list.append(data_test)

    #print(test_list)
    return ({
        "code": 20000,
        "data": {"data": test_list}
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

    data_none = {
        "data": [
            {
                'file_name': None,
                'file_hash': None,
                'thumb_print': None,
                'sign_algorithm': None,
                'subject_name': None,
                'valid_from': None,
                'valid_to': None
            }
        ]
    }

    # 获取表WeakCertRelationship中的信息
    weak_cert_relationship = dao.query_all_weak_cert_relation(None, None, firmware_hash)

    if (weak_cert_relationship is None or len(weak_cert_relationship) == 0):
        return ({"code": 20000, "data": data_none})

    id_WeakCert = []
    for weak_cert_relationship_item in weak_cert_relationship:
        id_WeakCert.append(weak_cert_relationship_item.id_WeakCert)

    test_list = []
    for id_WeakCert_item in id_WeakCert:
        weak_cert = dao.query_weak_cert(id_WeakCert_item,None, None, None, None, None, None, None)
        if(weak_cert is None):
            continue
        file_name = weak_cert.file_name
        file_hash = weak_cert.file_hash
        thumb_print = weak_cert.thumb_print
        sign_algorithm = weak_cert.sign_algorithm
        subject_name = weak_cert.subject_name
        valid_from = weak_cert.valid_from
        valid_to = weak_cert.valid_to

        data_test = {
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "sign_algorithm": sign_algorithm,
            "subject_name": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to
        }
        test_list.append(data_test)
    return ({
        "code": 20000,
        "data": {"data": test_list}
    })


def core_config_issues(firmware_hash):
    # test
    # data_temp2 = [
    #     {
    #         'service_name': 'Telnet',
    #         'config_file': '/etc/init.d/rcS',
    #         'issues': [
    #             'Result: telnet enabled in path'
    #         ],
    #         'suggestions': [
    #             'Disable telnet in path and use SSH instead'
    #         ]
    #     },
    #     {
    #         'service_name': 'Telnet',
    #         'config_file': '/etc/init.d/rcS.v2.0',
    #         'issues': [
    #             'Result: telnet enabled in path'
    #         ],
    #         'suggestions': [
    #             'Disable telnet in path and use SSH instead'
    #         ]
    #     },
    #     {
    #         'service_name': 'SNMP',
    #         'config_file': '/usr/local/etc/ippf/base/snmpd.conf',
    #         'issues': [
    #             'Result: found easy guessable snmp community string'
    #         ],
    #         'suggestions': [
    #             'Change public/private community strings to another value'
    #         ]
    #     }
    # ]
    # data_temp = {
    #     "data": data_temp2
    # }
    # return jsonify(
    #     {
    #         "code": 20000,
    #         "data": data_temp
    #     }
    # )

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

    # {
    #     'service_name': 'Telnet',
    #     'config_file': '/etc/init.d/rcS',
    #     'issues': [
    #         'Result: telnet enabled in path'
    #     ],
    #     'suggestions': [
    #         'Disable telnet in path and use SSH instead'
    #     ]
    # },

    data_none = {
        "data": [
            {
                'service_name': None,
                'config_file': None,
                'issues': None,
                'suggestions': None
            }
        ]
    }

    # 获取表ConfigIssueRelationship中的信息
    config_issue_relationship = dao.query_all_config_issue_relation(None, None, firmware_hash)

    if (config_issue_relationship is None or len(config_issue_relationship) == 0):
        return ({"code": 20000, "data": data_none})

    id_ConfigIssue = []
    for config_issue_relationship_item in config_issue_relationship:
        id_ConfigIssue.append(config_issue_relationship_item.id_ConfigIssue)

    test_list = []
    for id_ConfigIssue_item in id_ConfigIssue:
        config_issue = dao.query_config_issue(id_ConfigIssue_item,None, None, None, None)
        if(config_issue is None):
            continue
        service_name = config_issue.service_name
        config_file = config_issue.config_file
        issues = config_issue.issues
        suggestions = config_issue.suggestions

        data_test = {
            "service_name": service_name,
            "config_file": config_file,
            "issues": [issues],
            "suggestions": [suggestions]
        }
        test_list.append(data_test)
    print(test_list)
    return ({
        "code": 20000,
        "data": {"data": test_list}
    })


def core_extract_banner(start, length, banner):
    # data_temp_test = {"data":
    #     [
    #         {
    #             'manufacturer': 'Axis Communications AB',
    #             'model_name': 'P3346',
    #             'firmware_version': '5.20',
    #             'is_discontinued': "true",
    #             'cve_list': [
    #                 {
    #                     'cve_id': 'CVE-2018-10660',
    #                     'cvss': 10
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10662',
    #                     'cvss': 10
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10661',
    #                     'cvss': 10
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10658',
    #                     'cvss': 5
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10659',
    #                     'cvss': 5
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10663',
    #                     'cvss': 5
    #                 },
    #                 {
    #                     'cve_id': 'CVE-2018-10664',
    #                     'cvss': 5
    #                 }
    #             ],
    #             'device_type': 'IP Camera',
    #             'firmware_info': {
    #                 'name': 'AXIS P3346 5.20',
    #                 'version': '5.20',
    #                 'sha2': 'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175',
    #                 'release_date': '2010-12-03',
    #                 'download_url': 'http://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_20/P3346_5_20.bin'
    #             },
    #             'latest_firmware_info': {
    #                 'name': 'AXIS P3346 5.51.7.3',
    #                 'version': '5.51.7.3',
    #                 'sha2': 'a72361af68bd94f07cdf8b6c43389f4f382576bab752d4fb25dc74e93d4767a7',
    #                 'release_date': '2020-12-03',
    #                 'download_url': 'https://cdn.axis.com/ftp/pub_soft/MPQT/P3346/5_51_7_3/P3346_5_51_7_3.bin'
    #             }
    #         }, {
    #         'manufacturer': 'Omron',
    #         'model_name': 'PLC 3000',
    #         'firmware_version': '15.8',
    #         'device_type': 'PLC',
    #         'is_discontinued': 'True',
    #         'cve_list': [{
    #             'cve_id': 1,
    #             'cvss': 25
    #         },
    #             {
    #                 'cveId': 2,
    #                 'cvss': 35
    #             }],
    #         'firmware_info': [{
    #             'name': 'S7 - 1001',
    #             'version': '30.2',
    #             'sha2': 'shabbuhuiasd2131b2u23',
    #             'release_date': '2022.02.01',
    #             'download_url': 'www.google.com'
    #         }],
    #         'latest_firmware_info': {
    #             'name': 'S7 - 1001',
    #             'version': '30.2',
    #             'sha2': 'shabbuhuiasd2131b2u23',
    #             'release_date': '2022.02.01',
    #             'download_url': 'www.google.com'
    #         }
    #     }
    #     ]
    # }
    device_all = DeviceInfo.query.all()

    data_all = []

    try:
        for device_info in device_all:
            manufacturer = device_info.manufacturer
            model_name = device_info.model_name
            firmware_version = device_info.firmware_version
            is_discontinued = device_info.is_discontinued
            cve_list = device_info.cve_list
            device_type = device_info.device_type
            firmware_info = device_info.firmware_info
            latest_firmware_info = device_info.latest_firmware_info
            # 查找漏洞
            cve_all = []
            cve_list_id = cve_list.split(',')
            for i in cve_list_id:
                cve_i = dao.query_vulnerability(i)
                if (cve_i is not None):
                    cve_id = cve_i.cve_id
                    cvss = cve_i.cvss
                    cve = {
                        "cve_id": cve_id,
                        "cvss": cvss
                    }
                    cve_all.append(cve)

            # #查找最新的固件信息
            firmware_info = firmware_info.split(',')
            firmware_info_list = []
            for i in firmware_info:
                firmware_temp = dao.query_firmware_info(i)
                if (firmware_temp is not None):
                    name = firmware_temp.name
                    version = firmware_temp.version
                    sha2 = firmware_temp.sha2
                    release_date = firmware_temp.release_date
                    download_url = firmware_temp.download_url
                    firmware_info_list.append({
                        "name": name,
                        "version": version,
                        "sha2": sha2,
                        "release_date": release_date,
                        "download_url": download_url
                    })

            # 查找最新的固件信息
            latest_firmware_info = dao.query_firmware_info(latest_firmware_info)
            if (latest_firmware_info is not None):
                name = latest_firmware_info.name
                version = latest_firmware_info.version
                sha2 = latest_firmware_info.sha2
                release_date = latest_firmware_info.release_date
                download_url = latest_firmware_info.download_url
                latest_firmware_info = {
                    "name": name,
                    "version": version,
                    "sha2": sha2,
                    "release_date": release_date,
                    "download_url": download_url
                }

            dict = {
                "manufacturer": manufacturer,
                "model_name": model_name,
                "firmware_version": firmware_version,
                "is_discontinued": is_discontinued,
                "cve_list": cve_all,
                "device_type": device_type,
                "firmware_info": firmware_info_list,
                "latest_firmware_info": latest_firmware_info
            }
            data_all.append(dict)
            data2_all = {"data": data_all}
    except Exception as e:
        print(e)

    data_none = {
        "data": [
            {
                "manufacturer": None,
                "model_name": None,
                "firmware_version": None,
                "is_discontinued": None,
                "cve_list": None,
                "device_type": None,
                "firmware_info": None,
                "latest_firmware_info": None
            }
        ]
    }

    if banner is None or len(banner) == 0:
        return jsonify({'code': 20000, 'data': data2_all})
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
        #print("key is None")
        return jsonify({'code': 20000, 'data': data2_all})

    device_info1 = None

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
        return ({
            "code": 20000,
            "data": data_none
        })

    if (len(device_info1) == 0):
        return jsonify({
            "code": 20000,
            "data": data_none
        })

    id_info = []
    for i in device_info1:
        id_info.append(i.id)

    if (id_info is None):
        return {
            "code": 20000,
            "data": data_none
        }
    # 得到所有device_features的id
    id_device_features = []
    for i in range(0, len(device_info1)):
        id_device_features.append(device_info1[i].id)

    data = []

    # class DeviceInfo(db.Model):
    #     __tablename__ = 'device_info'
    #     id = db.Column(db.Integer, primary_key=True)
    #     manufacturer = db.Column(db.String(1024))
    #     model_name = db.Column(db.String(1024))
    #     firmware_version = db.Column(db.String(256))
    #     is_discontinued = db.Column(db.String(256))
    #     cve_list = db.Column(db.String(1024))  # List of CVES, refer to Vulnerability
    #     device_type = db.Column(db.String(256))
    #     firmware_info = db.Column(db.String(256))  # List of Device firmware information, refer to firmwareInfo
    #     latest_firmware_info = db.Column(db.Integer)  # Last Device firmware information, refer to firmwareInfo

    for i in range(0, len(id_device_features)):
        device_temp_info = dao.query_device_features_info_relation(None, id_device_features[i], None)
        id_device_info = device_temp_info.id_DeviceInfo
        device_info = dao.query_device_infor(id_device_info, None, None, None, None, None, None, None, None)

        manufacturer = device_info.manufacturer
        model_name = device_info.model_name
        firmware_version = device_info.firmware_version
        is_discontinued = device_info.is_discontinued
        cve_list = device_info.cve_list
        device_type = device_info.device_type
        firmware_info = device_info.firmware_info
        latest_firmware_info = device_info.latest_firmware_info
        # 查找漏洞
        cve_all = []
        cve_list_id = cve_list.split(',')
        for i in cve_list_id:
            cve_i = dao.query_vulnerability(i)
            if (cve_i is not None):
                cve_id = cve_i.cve_id
                cvss = cve_i.cvss
                cve = {
                    "cve_id": cve_id,
                    "cvss": cvss
                }
                cve_all.append(cve)

        # #查找最新的固件信息
        firmware_info = firmware_info.split(',')
        firmware_info_list = []
        for i in firmware_info:
            firmware_temp = dao.query_firmware_info(i)
            if (firmware_temp is not None):
                name = firmware_temp.name
                version = firmware_temp.version
                sha2 = firmware_temp.sha2
                release_date = firmware_temp.release_date
                download_url = firmware_temp.download_url
                firmware_info_list.append({
                    "name": name,
                    "version": version,
                    "sha2": sha2,
                    "release_date": release_date,
                    "download_url": download_url
                })

        # 查找最新的固件信息
        latest_firmware_info = dao.query_firmware_info(latest_firmware_info)
        if (latest_firmware_info is not None):
            name = latest_firmware_info.name
            version = latest_firmware_info.version
            sha2 = latest_firmware_info.sha2
            release_date = latest_firmware_info.release_date
            download_url = latest_firmware_info.download_url
            latest_firmware_info = {
                "name": name,
                "version": version,
                "sha2": sha2,
                "release_date": release_date,
                "download_url": download_url
            }

        dict = {
            "manufacturer": manufacturer,
            "model_name": model_name,
            "firmware_version": firmware_version,
            "is_discontinued": is_discontinued,
            "cve_list": cve_all,
            "device_type": device_type,
            "firmware_info": firmware_info_list,
            "latest_firmware_info": latest_firmware_info
        }
        data.append(dict)
        data2 = {"data": data}

    return ({'code': 20000, 'data': data2})
