import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import firmware


# class RiskSummary(db.Model):
#     __tablename__ = 'risk_summary'
#     id = db.Column(db.Integer, primary_key=True)
#
#     net_services_risk = db.Column(db.String(1024))
#     crypto_risk = db.Column(db.String(1024))
#     kernel_risk = db.Column(db.String(1024))
#     client_tools_risk = db.Column(db.String(1024))
# class VulnerableComponent(db.Model):
#     __tablename__ = 'vulnerable_component'
#     id = db.Column(db.Integer, primary_key=True)
#
#     name = db.Column(db.String(512))
#     version = db.Column(db.String(512))
#     category = db.Column(db.String(256))
#     vulnerabilities = db.Column(db.String(1024))
#     cvss_max = db.Column(db.Integer)

# class FirmwareRiskSummaryVulnerableComponentRelation(db.Model):
#     __tablename__ = 'firmware_risk_summary_vulnerable_component_relation'
#     id = db.Column(db.Integer, primary_key=True)
#     id_RiskSummary = db.Column(db.Integer) #Reference_key to RiskSummary
#     id_VulnerableComponent = db.Column(db.Integer)#Reference_key to VulnerableComponent
#     firmware_hash = db.Column(db.String(512)) #Reference_key to FirmwareInfo

#已测试
@firmware.route('/firmware/risk', methods=['POST'])
def view_firmware():
    #需要根据firmware_hash获取返回RiskSummary和VulnerableComponent的信息
    #因此创建表FirmwareRiskSummaryVulnerableComponentRelation

    #获取firmware_hash
    firmware_hash = request.form['firmware_hash']

    #获取表FirmwareRiskSummaryVulnerableComponentRelation中的信息
    firmware_risk_summary_vulnerable_component_relation = dao.query_firmware_risk_summary_vulnerable_component_relation(None, firmware_hash)

    if(firmware_risk_summary_vulnerable_component_relation is None):
        return "No Risk Summary and Vulnerable Component Relation"


    id_RiskSummary = firmware_risk_summary_vulnerable_component_relation.id_RiskSummary
    id_VulnerableComponent = firmware_risk_summary_vulnerable_component_relation.id_VulnerableComponent

    #获取表RiskSummary中的信息
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

    #获取表VulnerableComponent中的信
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

    #返回数据
    return jsonify({
        "net_services_risk": net_services_risk,
        "crypto_risk": crypto_risk,
        "kernel_risk": kernel_risk,
        "client_tools_risk": client_tools_risk,
        "name": name,
        "version": version,
        "category": category,
        "vulnerabilities": vulnerabilities,
        "cvss_max": cvss_max
    })

#已测试
@firmware.route('/firmware/accounts', methods=['POST'])
def view_firmware_accounts():

    firmware_hash = request.form['firmware_hash']

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

    #获取表DefaultAccountRelationship中的信息

    default_account_relationship = dao.query_default_account_relationship(None, None,firmware_hash)
    if(default_account_relationship is None):
        return "No Default Account Relationship"
    id_DefaultAccount = default_account_relationship.id_DefaultAccount
    if (id_DefaultAccount is None):
        return jsonify({
                "accounts": "No Default Account"
        })



    #获取表DefaultAccount中的信息

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

    #返回数据
    return jsonify({
        "accounts": [{
            "name": name,
            "pwd_hash": pwd_hash,
            "hash_algorithm": hash_algorithm,
            "shell": shell,
            "uid": uid,
            "gid": gid,
            "home_dir": home_dir
        }]
    })

#已测试
@firmware.route('/firmware/private-keys', methods=['POST'])
def view_firmware_private_keys():
    firmware_hash = request.form['firmware_hash']

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

    #获取表CryptoKeyRelationship中的信息
    crypto_key_relationship = dao.query_crypto_key_relation(None, None,firmware_hash)
    if(crypto_key_relationship is None):
        return "No Crypto Key Relationship"
    id_CryptoKey = crypto_key_relationship.id_CryptoKey

    #获取表CryptoKey中的信息
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

    return jsonify({
        "private_keys": [{
            "file_name": file_name,
            "file_hash": file_hash,
            "pem_type": pem_type,
            "algorithm": algorithm,
            "bits": str(bits)
        }]
    })
#已测试
@firmware.route('/firmware/weak-keys', methods=['POST'])
def view_firmware_weak_keys():
    firmware_hash = request.form['firmware_hash']

    firmware_hash = request.form['firmware_hash']

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
        bits = crypto_key.bits#过滤出较短的key
    except Exception as e:
        print(e)

    return jsonify({
        "private_keys": [{
            "file_name": file_name,
            "file_hash": file_hash,
            "pem_type": pem_type,
            "algorithm": algorithm,
            "bits": str(bits)
        }]
    })

#已测试
@firmware.route('/firmware/expired-certs', methods=['POST'])
def view_firmware_expired_certs():
    firmware_hash = request.form['firmware_hash']

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

    #获取表ExpiredCertRelationship中的信息
    expired_cert_relationship = dao.query_expired_cert_relation(None, None,firmware_hash)
    if(expired_cert_relationship is None):
        return jsonify({
            "expired_certs": []
        })
    id_ExpiredCert = expired_cert_relationship.id_ExpiredCert

    #获取表ExpiredCert中的信息
    file_name = ""
    file_hash = ""
    thumb_print = ""
    public_key = ""
    subject_name = ""
    valid_form = ""
    valid_to = ""
    try:
        expired_cert,public_key = dao.query_expired_cert(id_ExpiredCert, None, None, None, None, None, None,None,None,None)
        file_name = expired_cert.file_name
        file_hash = expired_cert.file_hash
        thumb_print = expired_cert.thumb_print
        public_key = expired_cert.public_key
        subject_name = expired_cert.subject_name
        valid_form = expired_cert.valid_form
        valid_to = expired_cert.valid_to
    except Exception as e:
        print(e)

    return jsonify({
        "expired_certs": [{
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "public_key": public_key,
            "subject_name": subject_name,
            "valid_form": valid_form,
            "valid_to": valid_to
        }]
    })

#已测试
@firmware.route('/firmware/weak-certs', methods=['POST'])
def view_firmware_weak_certs():
    firmware_hash = request.form['firmware_hash']

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

    #获取表WeakCertRelationship中的信息
    weak_cert_relationship = dao.query_weak_cert_relation(None, None, firmware_hash)

    if(weak_cert_relationship is None):
        return jsonify({
            "weak_certs": ""
        })

    id_WeakCert = weak_cert_relationship.id_WeakCert

    #获取表WeakCert中的信息
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

    return jsonify({
        "weak_certs": [{
            "file_name": file_name,
            "file_hash": file_hash,
            "thumb_print": thumb_print,
            "sign_algorithm": sign_algorithm,
            "subject_name": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to
        }]
    })
    return "weak-certs"

#已测试
@firmware.route('/firmware/config-issues', methods=['POST'])
def view_firmware_config_issues():
    firmware_hash = request.form['firmware_hash']

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
    #获取表ConfigIssueRelationship中的信息
    config_issue_relationship = dao.query_config_issue_relation(None, None, firmware_hash)
    if(config_issue_relationship is None):
        return jsonify({
            "config_issues": []
        })

    id_ConfigIssue = config_issue_relationship.id_ConfigIssue

    #获取表ConfigIssue中的信息
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

    return jsonify({
        "config_issues": [{
            "service_name": service_name,
            "config_file": config_file,
            "issues": issues,
            "suggestions": suggestions
        }]
    })