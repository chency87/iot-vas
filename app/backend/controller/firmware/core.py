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

    data_temp ={
  'risk_summary': {
    'net_services_risk': 'Critical',
    'crypto_risk': 'Critical',
    'kernel_risk': 'None',
    'client_tools_risk': 'High'
  },
  'vulnerable_components': [
    {
      'name': 'libupnp',
      'version': '1.4.1',
      'category': 'UPnP Server',
      'vulnerabilities': [
        {
          'cve_id': 'CVE-2012-5958',
          'cvss': 10
        },
        {
          'cve_id': 'CVE-2016-8863',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2020-13848',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2016-6255',
          'cvss': 5
        }
      ],
      'cvss_max': 10
    },
    {
      'name': 'openssl',
      'version': '0.9.7m',
      'category': 'Crypto Library',
      'vulnerabilities': [
        {
          'cve_id': 'CVE-2009-3245',
          'cvss': 10
        },
        {
          'cve_id': 'CVE-2016-2108',
          'cvss': 10
        },
        {
          'cve_id': 'CVE-2016-2109',
          'cvss': 7.8
        },
        {
          'cve_id': 'CVE-2010-0742',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2010-4252',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2012-2110',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2014-8176',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2015-0292',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2014-3567',
          'cvss': 7.1
        },
        {
          'cve_id': 'CVE-2012-2333',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2014-0195',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2015-0209',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2015-1791',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2016-2176',
          'cvss': 6.4
        },
        {
          'cve_id': 'CVE-2009-3555',
          'cvss': 5.8
        },
        {
          'cve_id': 'CVE-2014-0224',
          'cvss': 5.8
        },
        {
          'cve_id': 'CVE-2011-4354',
          'cvss': 5.8
        },
        {
          'cve_id': 'CVE-2008-5077',
          'cvss': 5.8
        },
        {
          'cve_id': 'CVE-2009-1387',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2006-7250',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2009-0789',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2009-1377',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2009-1378',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2009-4355',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2011-1473',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2011-4576',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2011-4619',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2012-0027',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2012-0884',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2012-1165',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2014-3570',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2014-3571',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2014-3572',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2014-8275',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-0286',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-0287',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-0288',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-0289',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-0293',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-1790',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-1792',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2016-2106',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2009-1386',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2013-0166',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2017-3735',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-4000',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2008-7270',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2010-0433',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2010-4180',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2011-4108',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2011-4577',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2013-6449',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2014-0221',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2014-3470',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2014-3568',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2015-0204',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2015-1788',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2015-1789',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2016-0703',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2016-0704',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2010-5298',
          'cvss': 4
        },
        {
          'cve_id': 'CVE-2016-2107',
          'cvss': 2.6
        },
        {
          'cve_id': 'CVE-2011-1945',
          'cvss': 2.6
        },
        {
          'cve_id': 'CVE-2016-7056',
          'cvss': 2.1
        },
        {
          'cve_id': 'CVE-2014-0076',
          'cvss': 1.9
        },
        {
          'cve_id': 'CVE-2007-3108',
          'cvss': 1.2
        }
      ],
      'cvss_max': 10
    },
    {
      'name': 'busybox',
      'version': '1.1.3',
      'category': 'Client Tool',
      'vulnerabilities': [
        {
          'cve_id': 'CVE-2016-6301',
          'cvss': 7.8
        },
        {
          'cve_id': 'CVE-2016-2148',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2018-1000517',
          'cvss': 7.5
        },
        {
          'cve_id': 'CVE-2013-1813',
          'cvss': 7.2
        },
        {
          'cve_id': 'CVE-2011-2716',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2018-1000500',
          'cvss': 6.8
        },
        {
          'cve_id': 'CVE-2017-16544',
          'cvss': 6.5
        },
        {
          'cve_id': 'CVE-2011-5325',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2016-2147',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2018-20679',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2019-5747',
          'cvss': 5
        },
        {
          'cve_id': 'CVE-2015-9261',
          'cvss': 4.3
        },
        {
          'cve_id': 'CVE-2014-9645',
          'cvss': 2.1
        }
      ],
      'cvss_max': 7.8
    },
    {
      'name': 'dbus',
      'version': '1.2.4',
      'category': 'Generic Server',
      'vulnerabilities': [
        {
          'cve_id': 'CVE-2011-2533',
          'cvss': 3.3
        }
      ],
      'cvss_max': 3.3
    }
  ]
}
    data_temp2 = {
        "data":data_temp
    }
    return jsonify(
        {
            "code": 20000,
            "data":data_temp2
        }
    )


    data_none={
        "data": [
            {
                "risk_summary":{
                    "net_services_risk": None,
                    "crypto_risk": None,
                    "kernel_risk": None,
                    "client_tools_risk": None
                },
                "vulnerable_components": {
                    "name": None,
                    "version": None,
                    "category": None,
                    "vulnerabilities": [
                        {
                            'cve_id': None,
                            'cvss':None,
                        }
                    ],
                }
            }
        ]
    }
    # 获取表FirmwareRiskSummaryVulnerableComponentRelation中的信息
    firmware_risk_summary_vulnerable_component_relation = dao.query_firmware_risk_summary_vulnerable_component_relation(
        None, firmware_hash)

    if (firmware_risk_summary_vulnerable_component_relation is None):
        return jsonify({"code": 20000, "data": data_none})

    id_RiskSummary = firmware_risk_summary_vulnerable_component_relation.id_RiskSummary
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
        dict_risk_summary = {
            'net_services_risk': net_services_risk,
            'crypto_risk': crypto_risk,
            'kernel_risk': kernel_risk,
            'client_tools_risk': client_tools_risk
        }
    except Exception as e:
        print(e)

    ids_VulnerableComponent=[]
    dict_vulnerable_components=[]
    for i in range(len(firmware_risk_summary_vulnerable_component_relation)):
        ids_VulnerableComponent.append(firmware_risk_summary_vulnerable_component_relation[i].id_VulnerableComponent)
        vulnerable_component = dao.query_vulnerable_component(firmware_risk_summary_vulnerable_component_relation[i].id_VulnerableComponent)
        name = ""
        version = ""
        category = ""
        cvss_max = ""
        vulnerabilities = ""
        try:
            name = vulnerable_component.name
            version = vulnerable_component.version
            category = vulnerable_component.category
            vulnerabilities = vulnerable_component.vulnerabilities
            cvss_max = vulnerable_component.cvss_max
            list_vulnerabilities = []
            ids = []
            cve_id = []
            cvss = []
            dict_vulnerabilities = []
            try:
                list_vulnerabilities = vulnerabilities.split(',')
                for i in range(len(list_vulnerabilities)):
                    ids.append(list_vulnerabilities[i])
                for i in range(len(ids)):
                    vulnerabilities_i = dao.query_vulnerability(ids[i])
                    dict_vulnerabilities.append({
                        "cve_id": vulnerabilities_i.cve_id,
                        "cvss": vulnerabilities_i.cvss
                    })
            except Exception as e:
                print(e)
        except Exception as e:
            print(e)
        dict_vulnerable_components.append({
            "name":name,
            "version":version,
            "category":category,
            "vulnerabilities":dict_vulnerabilities
        })
    newdata={
        "data":[
            {
                "risk_summary":dict_risk_summary,
                "vulnerable_components":dict_vulnerable_components
            }
        ]
    }
    # 返回数据
    return ({'code': 20000, 'data': newdata})


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
  default_account_relationship = dao.query_default_account_relationship(None, None, firmware_hash)
  if (default_account_relationship is None):
    return ({
      "code": 20000,
      "data": data_none,
    })
  id_DefaultAccount = default_account_relationship.id_DefaultAccount
  if (id_DefaultAccount is None):
    return ({
      "code": 20000,
      "data": data_none,
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

  # data_none = {
  #         "data": [
  #             {
  #             "manufacturer": None,
  #              "model_name": None,
  #              "firmware_version": None,
  #              "is_discontinued": None,
  #              "cve_list":None,
  #              "device_type": None,
  #              "firmware_info":None,
  #             "latest_firmware_info":None
  #             }
  #         ]
  #     }
  # 返回数据
  newdata = {
    "data": [
      {
        "name": name,
        "pwd_hash": pwd_hash,
        "hash_algorithm": hash_algorithm,
        "shell": shell,
        "uid": uid,
        "gid": gid,
        "home_dir": home_dir
      }
    ]
  }
  return ({"code": 20000, "data": newdata
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
    bits = crypto_key.bits
  except Exception as e:
    print(e)

  newdata = {
    "data": [
      {
        'file_name': file_name,
        'file_hash': file_hash,
        'pem_type': pem_type,
        'algorithm': algorithm,
        'bits': bits
      }
    ]
  }
  return ({
    "code": 20000,
    "data": newdata
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
        'public_key': {
          "algorithm": None,
          "bits": None
        },
        'subject_name': None,
        'valid_from': None,
        'valid_to': None,
      }
    ]
  }
  # 获取表ExpiredCertRelationship中的信息
  expired_cert_relationship = dao.query_expired_cert_relation(None, None, firmware_hash)
  if (expired_cert_relationship is None):
    return jsonify({
      "code": 20000, "data": data_none
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
  algorithm = ""
  bits = ""
  dict_public_key = ""
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
  public_key_table = dao.query_public_key(public_key)
  algorithm = public_key_table.algorithm
  bits = public_key_table.bits
  dict_public_key = {
    "algorithm": algorithm,
    "bits": bits
  }

  newdata = {
    "data": [
      {
        'file_name': file_name,
        'file_hash': file_hash,
        'thumb_print': thumb_print,
        'public_key': dict_public_key,
        'subject_name': subject_name,
        'valid_from': valid_form,
        'valid_to': valid_to
      }
    ]
  }
  return ({
    "code": 20000,
    "data": newdata
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
  weak_cert_relationship = dao.query_weak_cert_relation(None, None, firmware_hash)

  if (weak_cert_relationship is None):
    return ({"code": 20000, "data": data_none})

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

  newdata = {
    "data": [
      {
        'file_name': file_name,
        'file_hash': file_hash,
        'thumb_print': thumb_print,
        'sign_algorithm': sign_algorithm,
        'subject_name': subject_name,
        'valid_from': valid_from,
        'valid_to': valid_to
      }
    ]
  }

  return ({
    "code": 20000,
    "data": newdata
  })


def core_config_issues(firmware_hash):
    #test
#     data_temp2 =[
#   {
#     'service_name': 'Telnet',
#     'config_file': '/etc/init.d/rcS',
#     'issues': [
#       'Result: telnet enabled in path'
#     ],
#     'suggestions': [
#       'Disable telnet in path and use SSH instead'
#     ]
#   },
#   {
#     'service_name': 'Telnet',
#     'config_file': '/etc/init.d/rcS.v2.0',
#     'issues': [
#       'Result: telnet enabled in path'
#     ],
#     'suggestions': [
#       'Disable telnet in path and use SSH instead'
#     ]
#   },
#   {
#     'service_name': 'SNMP',
#     'config_file': '/usr/local/etc/ippf/base/snmpd.conf',
#     'issues': [
#       'Result: found easy guessable snmp community string'
#     ],
#     'suggestions': [
#       'Change public/private community strings to another value'
#     ]
#   }
# ]
#     data_temp ={
#         "data":data_temp2
#     }
#     return jsonify(
#         {
#             "code": 20000,
#             "data": data_temp
#         }
#     )


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

    # 获取表ConfigIssueRelationship中的信息
    config_issue_relationship = dao.query_all_config_issue_relation(None, None, firmware_hash)
    if (config_issue_relationship is None):
        return jsonify({
            "code":20000,
            "data":{
                'service_name': None,
                'config_file': None,
                'issues': None,
                'suggestions': None
            }
        })

    ConfigIssue_list = []

    for i in config_issue_relationship:
        config_issue_temp = dao.query_config_issue(i.id_ConfigIssue,None,None,None,None)
        ConfigIssue_list.append(
          {
            'service_name': config_issue_temp.service_name,
            'config_file': config_issue_temp.config_file,
            'issues': config_issue_temp.issues.split(','),
            'suggestions': config_issue_temp.suggestions.split(',')
          }
        )

    # 获取表ConfigIssue中的信息


    return ({
        "code": 20000,
        "data": ConfigIssue_list
    })


def core_extract_banner(start, length, banner):

    device_all = DeviceInfo.query.all()

    data_all = []

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
        return ({'code': 20000, 'data': data2_all})
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
        return {'code': 20000, 'data': data2_all}

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
        device_info = dao.query_device_infor(id_device_info, None, None, None, None, None, None,None,None)

        manufacturer = device_info.manufacturer
        model_name = device_info.model_name
        firmware_version = device_info.firmware_version
        is_discontinued = device_info.is_discontinued
        cve_list = device_info.cve_list
        device_type = device_info.device_type
        firmware_info = device_info.firmware_info
        latest_firmware_info = device_info.latest_firmware_info
        #查找漏洞
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

        #查找最新的固件信息
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
