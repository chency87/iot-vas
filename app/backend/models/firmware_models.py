from datetime import datetime
from distutils.command.config import config
import json


from app.backend.database.database import db

class DeviceInfo(db.Model):
    __tablename__ = 'device_info'
    id = db.Column(db.Integer, primary_key=True)
    manufacturer = db.Column(db.String(1024))
    model_name = db.Column(db.String(1024))
    firmware_version = db.Column(db.String(256))
    is_discontinued = db.Column(db.Boolean)
    cve_list = db.Column(db.String(1024)) # List of CVES, refer to Vulnerability
    device_type = db.Column(db.String(256))
    firmware_info = db.Column(db.String(256)) # List of Device firmware information, refer to firmwareInfo
    latest_firmware_info = db.Column(db.Integer) # Last Device firmware information, refer to firmwareInfo
    
    def __repr__(self):
        return "{id:'%s', manufacturer:'%s', model_name:'%s',firmware_version:'%s', is_discontinued:'%s', cve_list:'%s', device_type:'%s', firmware_info:'%s', latest_firmware_info:'%s' }" % (
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

class FirmwareInfo(db.Model):
    __tablename__ = 'firmware_info'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512))
    version = db.Column(db.String(512))
    sha2 = db.Column(db.String(512))
    release_date = db.Column(db.String(512))
    download_url = db.Column(db.String(512))

class ConfigIssue(db.Model):
    __tablename__ = 'config_issue'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(512))
    config_file = db.Column(db.String(512))
    issues = db.Column(db.String(512))  # List of detected issues
    suggestions = db.Column(db.String(512)) # List of suggestions to fix the issues

class CryptoKey(db.Model):
    __tablename__ = 'cryptokey'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    pem_type =  db.Column(db.String(512))
    algorithm =  db.Column(db.String(512))
    bits = db.Column(db.Integer)

class DefaultAccount(db.Model):
    __tablename__ = 'default_account'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512))
    pwd_hash = db.Column(db.String(512))
    hash_algorithm = db.Column(db.String(512)) #title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
    shell = db.Column(db.String(512))
    uid = db.Column(db.Integer)
    gid = db.Column(db.Integer)
    home_dir = db.Column(db.String(512))

class ExpiredCert(db.Model):
    __tablename__ = 'expired_cert'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    thumb_print = db.Column(db.String(512))
    public_key = db.Column(db.Integer) # public key , refer to  PublicKey
    subject_name = db.Column(db.String(512))
    valid_form = db.Column(db.String(512))
    valid_to =  db.Column(db.String(512))

class PublicKey(db.Model):
    __tablename__ = 'public_key'
    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(512))
    bits = db.Column(db.Integer)

class Vulnerability(db.Model):
    __tablename__ = 'vulnerability'
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(512))
    cvss = db.Column(db.Integer)

class VulnerableComponent(db.Model):
    __tablename__ = 'vulnerable_component'
    id = db.Column(db.Integer, primary_key=True)
    
    name = db.Column(db.String(512))
    version = db.Column(db.String(512))
    category = db.Column(db.String(256))
    vulnerabilities =  db.Column(db.String(1024))
    cvss_max = db.Column(db.Integer)

#PostServiceRealation
class PortServiceRelation(db.Model):
    __tablename__ = 'port_service_relation'
    id = db.Column(db.Integer, primary_key=True)

    connection_mode = db.Column(db.String(512))
    port = db.Column(db.Integer)
    service = db.Column(db.String(512))
    port_type = db.Column(db.Integer)   # 0:TCP static port 1:TCP dynamic port 2:UDP static port 3:UDP dynamic port

class FirmwareRisk(db.Model):
    __tablename__ = 'firmware_risk'
    id=db.Column(db.Integer,primary_key=True)

    risk_summary=db.Column(db.String(1024))
    vulnerable_components=db.Column(db.String(1024))

class RiskSummary(db.Model):
    __tablename__ = 'risk_summary'
    id = db.Column(db.Integer, primary_key=True)

    net_services_risk = db.Column(db.String(1024))
    crypto_risk = db.Column(db.String(1024))
    kernel_risk = db.Column(db.String(1024))
    client_tools_risk = db.Column(db.String(1024))

class WeakCert(db.Model):
    __tablename__ = 'weak_cert'
    id = db.Column(db.Integer, primary_key=True)

    file_name = db.Column(db.String(512))
    file_hash = db.Column(db.String(512))
    thumb_print = db.Column(db.String(512))
    sign_algorithm=db.Column(db.String(512))
    subject_name = db.Column(db.String(512))
    valid_from = db.Column(db.String(512))
    valid_to = db.Column(db.String(512))
class ValidationError(db.Model):
    __tablename__ = 'validation_error'
    id = db.Column(db.Integer, primary_key=True)

    loc = db.Column(db.String(512))
    msg = db.Column(db.String(512))
    type = db.Column(db.String(512))

class HTTPValidationError(db.Model):
    __tablename__ = 'http_validation_error'
    id = db.Column(db.Integer, primary_key=True)

    detail = db.Column(db.String(1024))

