from app.backend.database.database import db


class DeviceInfo(db.Model):
    __tablename__ = 'device_info'
    id = db.Column(db.Integer, primary_key=True)
    manufacturer = db.Column(db.String(1024))
    model_name = db.Column(db.String(1024))
    firmware_version = db.Column(db.String(256))
    is_discontinued = db.Column(db.String(256))
    cve_list = db.Column(db.String(1024))  # List of CVES, refer to Vulnerability
    device_type = db.Column(db.String(256))
    firmware_info = db.Column(db.String(256))  # List of Device firmware information, refer to firmwareInfo
    latest_firmware_info = db.Column(db.String(256))  # Last Device firmware information, refer to firmwareInfo

    def __repr__(self):
        return "{id:'%s', manufacturer:'%s', model_name:'%s',firmware_version:'%s', is_discontinued:'%s', " \
               "cve_list:'%s', device_type:'%s', firmware_info:'%s', latest_firmware_info:'%s' }" % (
                   self.id,
                   self.manufacturer,
                   self.model_name,
                   self.firmware_version,
                   self.is_discontinued,
                   self.cve_list,
                   self.device_type,
                   self.firmware_info,
                   self.latest_firmware_info
               )

    def to_json(self):
        json_post = {
            'id': self.id,
            'manufacturer': self.manufacturer,
            'model_name': self.model_name,
            'firmware_version': self.firmware_version,
            'is_discontinued': self.is_discontinued,
            'cve_list': self.cve_list,
            'device_type': self.device_type,
            'firmware_info': self.firmware_info,
            'latest_firmware_info': self.latest_firmware_info
        }
        return json_post


class DeviceFeatures(db.Model):
    __tablename__ = 'device_features'
    id = db.Column(db.Integer, primary_key=True)
    snmp_sysdescr = db.Column(db.String(512))
    snmp_sysoid = db.Column(db.String(512))
    ftp_banner = db.Column(db.String(256))
    telnet_banner = db.Column(db.String(256))
    hostname = db.Column(db.String(512))
    http_response = db.Column(db.String(512))
    https_response = db.Column(db.String(512))
    upnp_response = db.Column(db.String(512))
    nic_mac = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s', snmp_sysdescr:'%s', snmp_sysoid:'%s',ftp_banner:'%s', telnet_banner:'%s', hostname:'%s', http_response:'%s', https_response:'%s', upnp_response:'%s',nic_mac:'%s'}" % (
            self.id,
            self.snmp_sysdescr,
            self.snmp_sysoid,
            self.ftp_banner,
            self.telnet_banner,
            self.hostname,
            self.http_response,
            self.https_response,
            self.upnp_response,
            self.nic_mac
        )


class FirmwareInfo(db.Model):
    __tablename__ = 'firmware_info'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512))
    version = db.Column(db.String(512))
    sha2 = db.Column(db.String(512))
    release_date = db.Column(db.String(512))
    download_url = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s', name:'%s',version:'%s', sha2:'%s', release_date:'%s', download_url:'%s'}" % (
            self.id,
            self.name,
            self.version,
            self.sha2,
            self.release_date,
            self.download_url
        )


class ConfigIssue(db.Model):
    __tablename__ = 'config_issue'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(512))
    config_file = db.Column(db.String(512))
    issues = db.Column(db.String(512))  # List of detected issues
    suggestions = db.Column(db.String(512))  # List of suggestions to fix the issues

    def __repr__(self):
        return "{id:'%s', service_name:'%s',config_file:'%s', issues:'%s', suggestions:'%s'}" % (
            self.id,
            self.service_name,
            self.config_file,
            self.issues,
            self.suggestions
        )


class CryptoKey(db.Model):
    __tablename__ = 'cryptokey'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    pem_type = db.Column(db.String(512))
    algorithm = db.Column(db.String(512))
    bits = db.Column(db.Integer)

    def __repr__(self):
        return "{id:'%s', file_name:'%s',file_hash:'%s', pem_type:'%s', algorithm:'%s',bits:'%s'}" % (
            self.id,
            self.file_name,
            self.file_hash,
            self.pem_type,
            self.algorithm,
            self.bits
        )


class DefaultAccount(db.Model):
    __tablename__ = 'default_account'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512))
    pwd_hash = db.Column(db.String(512))
    hash_algorithm = db.Column(db.String(512))  # title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
    shell = db.Column(db.String(512))
    uid = db.Column(db.Integer)
    gid = db.Column(db.Integer)
    home_dir = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s', name:'%s',pwd_hash:'%s', hash_algorithm:'%s', shell:'%s',uid:'%s',gid:'%s',home_dir:'%s'}" % (
            self.id,
            self.name,
            self.pwd_hash,
            self.hash_algorithm,
            self.shell,
            self.uid,
            self.gid,
            self.home_dir
        )


class ExpiredCert(db.Model):
    __tablename__ = 'expired_cert'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    thumb_print = db.Column(db.String(512))
    public_key = db.Column(db.Integer)  # public key , refer to  PublicKey
    subject_name = db.Column(db.String(512))
    valid_form = db.Column(db.String(512))
    valid_to = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s', file_name:'%s',file_hash:'%s', thumb_print:'%s', public_key:'%s',subject_name:'%s',valid_form:'%s',valid_to:'%s'}" % (
            self.id,
            self.file_name,
            self.file_hash,
            self.thumb_print,
            self.public_key,
            self.subject_name,
            self.valid_form,
            self.valid_to
        )


class PublicKey(db.Model):
    __tablename__ = 'public_key'
    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(512))
    bits = db.Column(db.Integer)

    def __repr__(self):
        return "{id:'%s', algorithm:'%s',bits:'%s'}" % (
            self.id,
            self.algorithm,
            self.bits
        )


class Vulnerability(db.Model):
    __tablename__ = 'vulnerability'
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.Text)
    cvss = db.Column(db.String(256))

    def __repr__(self):
        return "{id:'%s', cve_id:'%s',cvss:'%s'}" % (
            self.id,
            self.cve_id,
            self.cvss
        )


class VulnerableComponent(db.Model):
    __tablename__ = 'vulnerable_component'
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(512))
    version = db.Column(db.String(512))
    category = db.Column(db.String(256))
    vulnerabilities = db.Column(db.String(1024))
    cvss_max = db.Column(db.Integer)

    def __repr__(self):
        return "{id:'%s', name:'%s', version:'%s', category:'%s', vulnerabilities:'%s', cvss_max:'%s' }" % (
            self.id,
            self.name,
            self.version,
            self.category,
            self.vulnerabilities,
            self.cvss_max
        )


# PostServiceRealation
class PortServiceRelation(db.Model):
    __tablename__ = 'port_service_relation'
    id = db.Column(db.Integer, primary_key=True)

    connection_mode = db.Column(db.String(512))
    port = db.Column(db.Integer)
    service = db.Column(db.String(512))
    port_type = db.Column(db.Integer)  # 0:TCP static port 1:TCP dynamic port 2:UDP static port 3:UDP dynamic port

    def __repr__(self):
        return "{id:'%s', connection_mode:'%s', port:'%s', service:'%s', port_type:'%s' }" % (
            self.id,
            self.connection_mode,
            self.port,
            self.service,
            self.port_type
        )


class FirmwareRisk(db.Model):
    __tablename__ = 'firmware_risk'
    id = db.Column(db.Integer, primary_key=True)

    risk_summary = db.Column(db.String(1024))
    vulnerable_components = db.Column(db.String(1024))

    def __repr__(self):
        return "{id:'%s', risk_summary:'%s', vulnerable_components:'%s' }" % (
            self.id,
            self.risk_summary,
            self.vulnerable_components
        )


class RiskSummary(db.Model):
    __tablename__ = 'risk_summary'
    id = db.Column(db.Integer, primary_key=True)

    net_services_risk = db.Column(db.String(1024))
    crypto_risk = db.Column(db.String(1024))
    kernel_risk = db.Column(db.String(1024))
    client_tools_risk = db.Column(db.String(1024))

    def __repr__(self):
        return "{id:'%s',net_services_risk:'%s',crypto_risk:'%s',kernel_risk:'%s',client_tools_risk:'%s'}" % (
            self.id, self.net_services_risk, self.crypto_risk, self.kernel_risk, self.client_tools_risk
        )


class WeakCert(db.Model):
    __tablename__ = 'weak_cert'
    id = db.Column(db.Integer, primary_key=True)

    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    thumb_print = db.Column(db.String(512))
    sign_algorithm = db.Column(db.String(512))
    subject_name = db.Column(db.String(512))
    valid_from = db.Column(db.String(512))
    valid_to = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s',file_name:'%s',file_hash:'%s',thumb_print:'%s',sign_algorithm:'%s',subject_name:'%s',valid_from:'%s',valid_to:'%s'}" % (
            self.id, self.file_name, self.file_hash, self.thumb_print, self.sign_algorithm, self.subject_name,
            self.valid_from, self.valid_to
        )


class ValidationError(db.Model):
    __tablename__ = 'validation_error'
    id = db.Column(db.Integer, primary_key=True)

    loc = db.Column(db.String(512))
    msg = db.Column(db.String(512))
    type = db.Column(db.String(512))

    def __repr__(self):
        return "{id:'%s',loc:'%s',msg:'%s',type:'%s'}" % (
            self.id, self.loc, self.msg, self.type
        )


class HTTPValidationError(db.Model):
    __tablename__ = 'http_validation_error'
    id = db.Column(db.Integer, primary_key=True)

    detail = db.Column(db.String(1024))

    def __repr__(self):
        return "{id:'%s',detail:'%s'}" % (
            self.id, self.detail
        )


class DeviceFeaturesInfoRelation(db.Model):
    __tablename__ = 'device_features_info_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_DeviceFeatures = db.Column(db.Integer)  # Reference_key to DeviceFeatures
    id_DeviceInfo = db.Column(db.Integer)  # Reference_key to DeviceInfo

    def __repr__(self):
        return "{id:'%s',id_DeviceFeatures:'%s',id_DeviceInfo:'%s'}" % (
            self.id, self.id_DeviceFeatures, self.id_DeviceInfo
        )


class FirmwareRiskSummaryVulnerableComponentRelation(db.Model):
    __tablename__ = 'firmware_risk_summary_vulnerable_component_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_RiskSummary = db.Column(db.Integer)  # Reference_key to RiskSummary
    id_VulnerableComponent = db.Column(db.Integer)  # Reference_key to VulnerableComponent
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:'%s',id_RiskSummary:'%s',id_VulnerableComponent:'%s',firmware_hash:'%s'}" % (
            self.id, self.id_RiskSummary, self.id_VulnerableComponent, self.firmware_hash
        )

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


class DefaultAccountRelationship(db.Model):
    __tablename__ = 'default_account_relationship'
    id = db.Column(db.Integer, primary_key=True)
    id_DefaultAccount = db.Column(db.Integer)  # Reference_key to DefaultAccount
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:'%s',id_DefaultAccount:'%s',firmware_hash:'%s'}" % (
            self.id, self.id_DefaultAccount, self.firmware_hash
        )


class CryptoKeyRelation(db.Model):
    __tablename__ = 'crypto_key_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_CryptoKey = db.Column(db.Integer)  # Reference_key to CryptoKey
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:'%s',id_CryptoKey:'%s',firmware_hash:'%s'}" % (
            self.id, self.id_CryptoKey, self.firmware_hash
        )


class WeakCertRelation(db.Model):
    __tablename__ = 'weak_cert_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_WeakCert = db.Column(db.Integer)  # Reference_key to WeakCert
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:'%s',id_WeakCert:'%s',firmware_hash:'%s'}" % (
            self.id, self.id_WeakCert, self.firmware_hash
        )


# class ConfigIssue(db.Model):
#     __tablename__ = 'config_issue'
#     id = db.Column(db.Integer, primary_key=True)
#     service_name = db.Column(db.String(512))
#     config_file = db.Column(db.String(512))
#     issues = db.Column(db.String(512))  # List of detected issues
#     suggestions = db.Column(db.String(512)) # List of suggestions to fix the issues
class ConfigIssueRelation(db.Model):
    __tablename__ = 'config_issue_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_ConfigIssue = db.Column(db.Integer)  # Reference_key to ConfigIssue
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:''%s',id_ConfigIssue:'%s' 'firmware_hash':'%s'}" % (
        self.id, self.id_ConfigIssue, self.firmware_hash)


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

class ExpiredCertRelation(db.Model):
    __tablename__ = 'expired_cert_relation'
    id = db.Column(db.Integer, primary_key=True)
    id_ExpiredCert = db.Column(db.Integer)  # Reference_key to ExpiredCert
    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    def __repr__(self):
        return "{id:'%s',id_ExpiredCert:'%s',firmware:'%s'}" % (
            self.id, self.id_ExpiredCert, self.firmware_hash
        )
