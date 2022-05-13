import bdb

from app.backend.models.firmware_models import *

# CryptoKey
def add_update_crypto_key(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        cryptokey = CryptoKey.query.filter_by(id=id).first()
        cryptokey.file_name=file_name if file_name else cryptokey.file_name
        cryptokey.file_hash=file_hash if file_hash else cryptokey.file_hash
        cryptokey.pem_type=pem_type if pem_type else cryptokey.pem_type
        cryptokey.algorithm=algorithm if algorithm else cryptokey.algorithm
        cryptokey.bits=bits if bits else cryptokey.bits
        db.session.commit()
    else:
        current = CryptoKey.query.filter_by(file_name=file_name,file_hash=file_hash).first()
        if current:
            return None
        data = dict(
            file_name=str(file_name),
            file_hash=str(file_hash),
            pem_type=str(pem_type),
            algorithm=str(algorithm),
            bits=bits
        )
        df = CryptoKey(**data)

        db.session.add(df)
        db.session.commit()

def delete_crypto_key(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        cryptokey = CryptoKey.query.filter_by(id=id).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif file_name:
        cryptokey = CryptoKey.query.filter_by(file_name=file_name).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif file_hash:
        cryptokey = CryptoKey.query.filter_by(file_hash=file_hash).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif pem_type:
        cryptokey = CryptoKey.query.filter_by(pem_type=pem_type).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif algorithm:
        cryptokey = CryptoKey.query.filter_by(algorithm=algorithm).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif bits:
        cryptokey = CryptoKey.query.filter_by(bits=bits).first()
        db.session.delete(cryptokey)
        db.session.commit()

def query_crypto_key(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        return CryptoKey.query.filter_by(id=id).first()
    elif file_name:
        return CryptoKey.query.filter_by(file_name=file_name).first()
    elif file_hash:
        return CryptoKey.query.filter_by(file_hash=file_hash).first()
    elif pem_type:
        return CryptoKey.query.filter_by(pem_type=pem_type).first()
    elif algorithm:
        return CryptoKey.query.filter_by(algorithm=algorithm).first()
    elif bits:
        return CryptoKey.query.filter_by(bits=bits).first()

# ConfigIssue
# id = db.Column(db.Integer, primary_key=True)
# service_name = db.Column(db.String(512))
# config_file = db.Column(db.String(512))
# issues = db.Column(db.String(512))  # List of detected issues
# suggestions = db.Column(db.String(512)) # List of suggestions to fix the issues
def add_update_config_issue(id, service_name, config_file , issues, suggestions):
    if id:
        configIssue = ConfigIssue.query.filter_by(id=id).first()
        configIssue.service_name=service_name if service_name else configIssue.service_name
        configIssue.config_file=config_file if config_file else configIssue.config_file
        configIssue.issues=issues if issues else configIssue.issues
        configIssue.suggestions=suggestions if suggestions else configIssue.suggestions
        db.session.commit()
    else:
        current = ConfigIssue.query.filter_by(service_name=service_name,config_file=config_file).first()
        if current:
            return None
        data = dict(
            service_name=str(service_name),
            config_file=str(config_file),
            issues=str(issues),
            algorithm=str(suggestions)
        )
        df = ConfigIssue(**data)

        db.session.add(df)
        db.session.commit()

def delete_config_issue(id, service_name, config_file , issues, suggestions):
    if id:
        configIssue = ConfigIssue.query.filter_by(id=id).first()
    elif service_name:
        configIssue = ConfigIssue.query.filter_by(service_name=service_name).first()
    elif config_file:
        configIssue = ConfigIssue.query.filter_by(config_file=config_file).first()
    elif issues:
        configIssue = ConfigIssue.query.filter_by(issues=issues).first()
    elif suggestions:
        configIssue = ConfigIssue.query.filter_by(suggestions=suggestions).first()
    db.session.delete(configIssue)
    db.session.commit()

def query_config_issue(id, service_name, config_file , issues, suggestions):
    if id:
        return ConfigIssue.query.filter_by(id=id).first()
    elif service_name:
        return ConfigIssue.query.filter_by(service_name=service_name).first()
    elif config_file:
        return ConfigIssue.query.filter_by(config_file=config_file).first()
    elif issues:
        return ConfigIssue.query.filter_by(issues=issues).first()
    elif suggestions:
        return ConfigIssue.query.filter_by(suggestions=suggestions).first()

# DefaultAccount:
#     __tablename__ = 'default_account'
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(512))
#     pwd_hash = db.Column(db.String(512))
#     hash_algorithm = db.Column(db.String(512)) #title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
#     shell = db.Column(db.String(512))
#     uid = db.Column(db.Integer)
#     gid = db.Column(db.Integer)
#     home_dir = db.Column(db.String(512))
def add_update_default_account(id, name, pwd_hash , hash_algorithm, shell,uid,gid,home_dir):
    if id:
        defaultaccount=DefaultAccount.query.filter_by(id=id).first()
        defaultaccount.name=name if name else defaultaccount.name
        defaultaccount.pwd_hash=pwd_hash if pwd_hash else defaultaccount.pwd_hash
        defaultaccount.hash_algorithm=hash_algorithm if hash_algorithm else defaultaccount.hash_algorithm
        defaultaccount.shell=shell if shell else defaultaccount.shell
        defaultaccount.uid=uid if uid else defaultaccount.uid
        defaultaccount.gid=gid if gid else defaultaccount.gid
        defaultaccount.home_dir=home_dir if home_dir else defaultaccount.home_dir
        db.session.commit()
    else:
        current = DefaultAccount.query.filter_by(name=name).first()
        if current:
            return None
        data = dict(
            name=str(name),
            pwd_hash=str(pwd_hash),
            hash_algorithm=str(hash_algorithm),
            shell=str(shell),
            uid=uid,
            gid=gid,
            home_dir=str(home_dir)
        )
        df = DefaultAccount(**data)

        db.session.add(df)
        db.session.commit()

def delete_default_account(id, name, pwd_hash , hash_algorithm, shell,uid,gid,home_dir):
    if id:
        defaultaccount = DefaultAccount.query.filter_by(id=id).first()
    elif name:
        defaultaccount = DefaultAccount.query.filter_by(name=name).first()
    elif pwd_hash:
        defaultaccount = DefaultAccount.query.filter_by(pwd_hash=pwd_hash).first()
    elif hash_algorithm:
        defaultaccount = DefaultAccount.query.filter_by(hash_algorithm=hash_algorithm).first()
    elif shell:
        defaultaccount = DefaultAccount.query.filter_by(shell=shell).first()
    elif uid:
        defaultaccount = DefaultAccount.query.filter_by(uid=uid).first()
    elif gid:
        defaultaccount = DefaultAccount.query.filter_by(gid=gid).first()
    elif home_dir:
        defaultaccount = DefaultAccount.query.filter_by(home_dir=home_dir).first()

    db.session.delete(defaultaccount)
    db.session.commit()

def query_default_account(id, name, pwd_hash , hash_algorithm, shell,uid,gid,home_dir):
    if id:
        return DefaultAccount.query.filter_by(id=id).first()
    elif name:
        return DefaultAccount.query.filter_by(name=name).first()
    elif pwd_hash:
        return DefaultAccount.query.filter_by(pwd_hash=pwd_hash).first()
    elif hash_algorithm:
        return DefaultAccount.query.filter_by(hash_algorithm=hash_algorithm).first()
    elif shell:
        return DefaultAccount.query.filter_by(shell=shell).first()
    elif uid:
        return DefaultAccount.query.filter_by(uid=uid).first()
    elif gid:
        return DefaultAccount.query.filter_by(gid=gid).first()
    elif home_dir:
        return DefaultAccount.query.filter_by(home_dir=home_dir).first()

# DeviceFeatures(db.Model):
#     __tablename__ = 'device_features'
#     id = db.Column(db.Integer, primary_key=True)
#     snmp_sysdescr = db.Column(db.String(512))
#     snmp_sysoid = db.Column(db.String(512))
#     ftp_banner = db.Column(db.String(256))
#     telnet_banner = db.Column(db.String(256))
#     hostname = db.Column(db.String(512))
#     http_response = db.Column(db.String(512))
#     https_response = db.Column(db.String(512))
#     upnp_response = db.Column(db.String(512))
#     nic_mac = db.Column(db.String(512))
def add_update_device_features(id, snmp_sysdescr, snmp_sysoid , ftp_banner, telnet_banner,hostname,http_response,https_response,upnp_response,nic_mac):
    if id:
        devicefeatures=DeviceFeatures.query.filter_by(id=id).first()
        devicefeatures.snmp_sysdescr=snmp_sysdescr if snmp_sysdescr else devicefeatures.snmp_sysdescr
        devicefeatures.snmp_sysoid=snmp_sysoid if snmp_sysdescr else devicefeatures.snmp_sysoid
        devicefeatures.ftp_banner=ftp_banner if ftp_banner else devicefeatures.ftp_banner
        devicefeatures.telnet_banner=telnet_banner if telnet_banner else devicefeatures.telnet_banner
        devicefeatures.hostname=hostname if hostname else devicefeatures.hostname
        devicefeatures.http_response=http_response if http_response else devicefeatures.http_response
        devicefeatures.https_response=https_response if https_response else devicefeatures.https_response
        devicefeatures.upnp_response=upnp_response if upnp_response else devicefeatures.upnp_response
        devicefeatures.nic_mac=nic_mac if nic_mac else devicefeatures.nic_mac
        db.session.commit()
    else:
        current = DeviceFeatures.query.filter_by(snmp_sysdescr=snmp_sysdescr).first()
        if current:
            return None
        data = dict(
            snmp_sysdescr=str(snmp_sysdescr),
            snmp_sysoid=str(snmp_sysoid),
            ftp_banner=str(ftp_banner),
            telnet_banner=str(telnet_banner),
            hostname=str(hostname),
            http_response=str(http_response),
            https_response=str(https_response),
            upnp_response=str(upnp_response),
            nic_mac=str(nic_mac)
        )
        df = DeviceFeatures(**data)

        db.session.add(df)
        db.session.commit()

def delete_device_features(id, snmp_sysdescr, snmp_sysoid , ftp_banner, telnet_banner,hostname,http_response,https_response,upnp_response,nic_mac):
    if id:
        devicefeatures = DeviceFeatures.query.filter_by(id=id).first()
    elif snmp_sysdescr:
        devicefeatures = DeviceFeatures.query.filter_by(snmp_sysdescr=snmp_sysdescr).first()
    elif snmp_sysoid:
        devicefeatures = DeviceFeatures.query.filter_by(snmp_sysoid=snmp_sysoid).first()
    elif ftp_banner:
        devicefeatures = DeviceFeatures.query.filter_by(ftp_banner=ftp_banner).first()
    elif telnet_banner:
        devicefeatures = DeviceFeatures.query.filter_by(telnet_banner=telnet_banner).first()
    elif hostname:
        devicefeatures = DeviceFeatures.query.filter_by(hostname=hostname).first()
    elif http_response:
        devicefeatures = DeviceFeatures.query.filter_by(http_response=http_response).first()
    elif https_response:
        devicefeatures = DeviceFeatures.query.filter_by(https_response=https_response).first()
    elif upnp_response:
        devicefeatures = DeviceFeatures.query.filter_by(upnp_response=upnp_response).first()
    elif nic_mac:
        devicefeatures = DeviceFeatures.query.filter_by(nic_mac=nic_mac).first()

    db.session.delete(devicefeatures)
    db.session.commit()

def query_device_features(id, snmp_sysdescr, snmp_sysoid , ftp_banner, telnet_banner,hostname,http_response,https_response,upnp_response,nic_mac):
    if id:
        return DeviceFeatures.query.filter_by(id=id).first()
    elif snmp_sysdescr:
        return DeviceFeatures.query.filter_by(snmp_sysdescr=snmp_sysdescr).first()
    elif snmp_sysoid:
        return DeviceFeatures.query.filter_by(snmp_sysoid=snmp_sysoid).first()
    elif ftp_banner:
        return DeviceFeatures.query.filter_by(ftp_banner=ftp_banner).first()
    elif telnet_banner:
        return DeviceFeatures.query.filter_by(telnet_banner=telnet_banner).first()
    elif hostname:
        return DeviceFeatures.query.filter_by(hostname=hostname).first()
    elif http_response:
        return DeviceFeatures.query.filter_by(http_response=http_response).first()
    elif https_response:
        return DeviceFeatures.query.filter_by(https_response=https_response).first()
    elif upnp_response:
        return DeviceFeatures.query.filter_by(upnp_response=upnp_response).first()
    elif nic_mac:
        return DeviceFeatures.query.filter_by(nic_mac=nic_mac).first()

# DeviceInfo(db.Model):
#     __tablename__ = 'device_info'
#     id = db.Column(db.Integer, primary_key=True)
#     manufacturer = db.Column(db.String(1024))
#     model_name = db.Column(db.String(1024))
#     firmware_version = db.Column(db.String(256))
#     is_discontinued = db.Column(db.Boolean)
#     cve_list = db.Column(db.String(1024)) # List of CVES, refer to Vulnerability
#     device_type = db.Column(db.String(256))
#     firmware_info = db.Column(db.String(256)) # List of Device firmware information, refer to firmwareInfo
#     latest_firmware_info = db.Column(db.Integer) # Last Device firmware information, refer to firmwareInfo
# Vulnerability(db.Model):
#     __tablename__ = 'vulnerability'
#     id = db.Column(db.Integer, primary_key=True)
#     cve_id = db.Column(db.String(512))
#     cvss = db.Column(db.Integer)
# FirmwareInfo(db.Model):
#     __tablename__ = 'firmware_info'
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(512))
#     version = db.Column(db.String(512))
#     sha2 = db.Column(db.String(512))
#     release_date = db.Column(db.String(512))
#     download_url = db.Column(db.String(512))


def add_update_device_infor(id, manufacturer, model_name, firmware_version, is_discontinued,cve_list,device_type,firmware_info,latest_firmware_info,cve_id,cvss,name,version,sha2,release_date,download_url):
    if id:
        deviceinfor=DeviceInfo.query.filter_by(id=id).first()
        deviceinfor.manufacturer=manufacturer if manufacturer else deviceinfor.manufacturer
        deviceinfor.model_name=model_name if model_name else deviceinfor.model_name
        deviceinfor.firmware_version=firmware_version if firmware_version else deviceinfor.firmware_version
        deviceinfor.is_discontinued=is_discontinued if is_discontinued else is_discontinued
        deviceinfor.cve_list=cve_list if cve_list else deviceinfor.cve_list
        deviceinfor.device_type=device_type if device_type else deviceinfor.device_type
        deviceinfor.firmware_info=firmware_info if firmware_info else deviceinfor.firmware_info
        deviceinfor.latest_firmware_info=latest_firmware_info if latest_firmware_info else deviceinfor.latest_firmware_info

        vulnerability=Vulnerability.query.filter_by(id=id).first()
        vulnerability.cve_id=cve_id if cve_id else vulnerability.cve_id
        vulnerability.cvss=cvss if cvss else vulnerability.cvss

        firminfor=FirmwareInfo.query.filter_by(id=id).first()
        firminfor.name=name if name else firminfor.name
        firminfor.version=version if version else firminfor.version
        firminfor.sha2=sha2 if sha2 else firminfor.sha2
        firminfor.release_date=release_date if release_date else firminfor.release_date
        firminfor.download_url=download_url if download_url else firminfor.download_url

        db.session.commit()
    else:
        current = DeviceInfo.query.filter_by(manufacturer=manufacturer).first()#没有写完这里
        if current:
            return None
        data = dict(
            manufacturer=str(manufacturer),
            model_name=str(model_name),
            firmware_version=str(firmware_version),
            is_discontinued=is_discontinued,
            cve_list=str(cve_list),
            device_type=str(device_type),
            firmware_info=str(firmware_info),
            latest_firmware_info=latest_firmware_info
        )
        data0=dict(
            cve_id=str(cve_id),
            cvss=cvss
        )
        data1=dict(
            name=str(name),
            version=str(version),
            sha2=str(sha2),
            release_date=str(release_date),
            download_url=str(download_url)
        )
        df = DeviceInfo(**data)
        df0=Vulnerability(**data0)
        df1=FirmwareInfo(**data1)

        db.session.add(df)
        db.session.add(df0)
        db.session.add(df1)
        db.session.commit()

def delete_device_infor(id, manufacturer, model_name, firmware_version, is_discontinued,cve_list,device_type,firmware_info,latest_firmware_info,cve_id,cvss,name,version,sha2,release_date,download_url):
    if id:
        deviceinfor = DeviceInfo.query.filter_by(id=id).first()
        vulnerability = Vulnerability.query.filter_by(id=id).first()
        firminfor = FirmwareInfo.query.filter_by(id=id).first()

    db.session.delete(deviceinfor)
    db.session.delete(vulnerability)
    db.session.delete(firminfor)
    db.session.commit()#找不到对应id？？删除失败？？？

def query_device_infor(id, manufacturer, model_name, firmware_version, is_discontinued,cve_list,device_type,firmware_info,latest_firmware_info,cve_id,cvss,name,version,sha2,release_date,download_url):
    if id:
        return DeviceFeatures.query.filter_by(id=id).first(),Vulnerability.query.filter_by(id=id).first(),FirmwareInfo.query.filter_by(id=id).first()

# ExpiredCert(db.Model):
    # __tablename__ = 'expired_cert'
    # id = db.Column(db.Integer, primary_key=True)
    # file_name = db.Column(db.String(512))
    # file_hash = db.Column(db.String(512))
    # thumb_print = db.Column(db.String(512))
    # public_key = db.Column(db.Integer)  # public key , refer to  PublicKey
    # subject_name = db.Column(db.String(512))
    # valid_form = db.Column(db.String(512))
    # valid_to = db.Column(db.String(512))
# PublicKey(db.Model):
#     __tablename__ = 'public_key'
#     id = db.Column(db.Integer, primary_key=True)
#     algorithm = db.Column(db.String(512))
#     bits = db.Column(db.Integer)
def add_update_expired_cert(id, file_name, file_hash , thumb_print, public_key,subject_name,valid_form,valid_to,algorithm,bits):
    if id:
        expiredcert=ExpiredCert.query.filter_by(id=id).first()
        expiredcert.file_name=file_name if file_name else expiredcert.file_name
        expiredcert.file_hash=file_name if file_hash else expiredcert.file_hash
        expiredcert.thumb_print=thumb_print if thumb_print else expiredcert.thumb_print
        expiredcert.public_key=public_key if public_key else expiredcert.public_key
        expiredcert.subject_name=subject_name if subject_name else expiredcert.subject_name
        expiredcert.valid_form=valid_form if valid_form else expiredcert.valid_form
        expiredcert.valid_to=valid_to if valid_to else expiredcert.valid_to

        publickey=PublicKey.query.filter_by(id=id).first()
        publickey.algorithm=algorithm if algorithm else publickey.algorithm
        publickey.bits=bits if bits else publickey.bits


        db.session.commit()
    else:
        current = ExpiredCert.query.filter_by(file_name=file_name,file_hash=file_hash).first()
        current0= PublicKey.query.filter_by(algorithm=algorithm,bits=bits)
        if current and current0:
            return None
        data = dict(
            file_name=str(file_name),
            file_hash=str(file_hash),
            thumb_print=str(thumb_print),
            public_key=public_key,
            subject_name=str(subject_name),
            valid_form=str(valid_form),
            valid_to=str(valid_to)
        )
        data0=dict(
            algorithm=str(algorithm),
            bits=bits
        )
        df = ExpiredCert(**data)
        df0=PublicKey(**data0)


        db.session.add(df)
        db.session.add(df0)
        db.session.commit()

def delete_expired_cert(id, file_name, file_hash , thumb_print, public_key,subject_name,valid_form,valid_to,algorithm,bits):
    if id:
        expiredcert = ExpiredCert.query.filter_by(id=id).first()
        publickey = PublicKey.query.filter_by(id=id).first()

    db.session.delete(expiredcert)
    db.session.delete(publickey)
    db.session.commit()

def query_expired_cert(id, file_name, file_hash , thumb_print, public_key,subject_name,valid_form,valid_to,algorithm,bits):
    if id:
        return ExpiredCert.query.filter_by(id=id).first(),PublicKey.query.filter_by(id=id).first()

# FirmwareRisk(db.Model):
#     __tablename__ = 'firmware_risk'
#     id=db.Column(db.Integer,primary_key=True)
#
#     risk_summary=db.Column(db.String(1024))
#     vulnerable_components=db.Column(db.String(1024))
# RiskSummary(db.Model):
#     __tablename__ = 'risk_summary'
#     id = db.Column(db.Integer, primary_key=True)
#
#     net_services_risk = db.Column(db.String(1024))
#     crypto_risk = db.Column(db.String(1024))
#     kernel_risk = db.Column(db.String(1024))
#     client_tools_risk = db.Column(db.String(1024))

# VulnerableComponent(db.Model):
# __tablename__ = 'vulnerable_component'
# id = db.Column(db.Integer, primary_key=True)
#
# name = db.Column(db.String(512))
# version = db.Column(db.String(512))
# category = db.Column(db.String(256))
# vulnerabilities = db.Column(db.String(1024))
# cvss_max = db.Column(db.Integer)

# Vulnerability(db.Model):
#     __tablename__ = 'vulnerability'
#     id = db.Column(db.Integer, primary_key=True)
#     cve_id = db.Column(db.String(512))
#     cvss = db.Column(db.Integer)

def add_update_firmware_risk(id,risk_summary ,net_services_risk,crypto_risk,kernel_risk,client_tools_risk, vulnerable_components ,name,version,category,vulnerabilities,cvss_max, cve_id,cvss):
    if id:
        firmwarerisk=FirmwareRisk.query.filter_by(id=id).first()
        firmwarerisk.risk_summary=risk_summary if risk_summary else firmwarerisk.risk_summary
        firmwarerisk.vulnerable_components=vulnerable_components if vulnerable_components else firmwarerisk.vulnerable_components

        risksummary=RiskSummary.query.filter_by(id=id).first()
        risksummary.net_services_risk = net_services_risk if net_services_risk else risksummary.net_services_risk
        risksummary.crypto_risk = crypto_risk if crypto_risk else risksummary.crypto_risk
        risksummary.kernel_risk = kernel_risk if kernel_risk else risksummary.kernel_risk
        risksummary.client_tools_risk = client_tools_risk if client_tools_risk else risksummary.client_tools_risk

        vulnerablecomponents=VulnerableComponent.query.filter_by(id=id).first()
        vulnerablecomponents.name=name if name else vulnerablecomponents.name
        vulnerablecomponents.version=version if version else vulnerablecomponents.version
        vulnerablecomponents.category=category if category else vulnerablecomponents.category
        vulnerablecomponents.vulnerabilities=vulnerabilities if vulnerabilities else vulnerablecomponents.vulnerabilities
        vulnerablecomponents.cvss_max=cvss_max if cvss else vulnerablecomponents.cvss_max

        vulnerability=Vulnerability.query.filter_by(id=id).first()
        vulnerability.cve_id=cve_id if cve_id else vulnerability.cve_id
        vulnerability.cvss =cvss if cvss else vulnerability.cvss

        db.session.commit()
    else:
        current = FirmwareRisk.query.filter_by(risk_summary_net_services_risk=net_services_risk).first()
        current0= VulnerableComponent.query.filter_by(name=name)
        current1=Vulnerability.query.filter_by(cve_id=cve_id).first()
        if current and current0 and current1:
            return None
        data = dict(
            risk_summary=str(risk_summary),
            vulnerable_components=str(vulnerable_components)
        )
        datax=dict(
            net_services_risk=str(net_services_risk),
            crypto_risk=str(crypto_risk),
            kernel_risk=str(kernel_risk),
            client_tools_risk=str(client_tools_risk),
        )
        data0=dict(
            name=str(name),
            version=str(version),
            category=str(category),
            vulnerabilities=str(vulnerabilities),
            cvss_max=cvss_max
        )
        data1=dict(
            cve_id=str(cve_id),
            cvss=cvss
        )
        df = FirmwareRisk(**data)
        dfx=RiskSummary(**datax)
        df0=VulnerableComponent(**data0)
        df1=Vulnerability(**data1)

        db.session.add(df)
        db.session.add(df0)
        db.session.add(df1)
        db.session.commit()

def delete_firmware_risk(id,risk_summary ,net_services_risk,crypto_risk,kernel_risk,client_tools_risk, vulnerable_components ,name,version,category,vulnerabilities,cvss_max, cve_id,cvss):
    if id:
        firmwarerisk= FirmwareRisk.query.filter_by(id=id).first()
        risksummary=RiskSummary.query.filter_by(id=id).first()
        vulnerablecomponent = VulnerableComponent.query.filter_by(id=id).first()
        vulnerability=Vulnerability.query.filter_by(id=id).first()

    db.session.delete(firmwarerisk)
    db.session.delete(risksummary)
    db.session.delete(vulnerablecomponent)
    db.session.delete(vulnerability)
    db.session.commit()

def query_firmware_risk(id, risk_summary_net_services_risk,risk_summary_crypto_risk,risk_summary_kernel_risk,risk_summary_client_tools_risk, vulnerable_components ,name,version,category,vulnerabilities,cvss_max, cve_id,cvss):
    if id:
        return FirmwareRisk.query.filter_by(id=id).first(),RiskSummary.query.filter_by(id=id).first(),VulnerableComponent.query.filter_by(id=id).first(),Vulnerability.query.filter_by(id=id).first()

# WeakCert(db.Model):
# __tablename__ = 'weak_cert'
# id = db.Column(db.Integer, primary_key=True)
#
# file_name = db.Column(db.String(512))
# file_hash = db.Column(db.String(512))
# thumb_print = db.Column(db.String(512))
# sign_algorithm = db.Column(db.String(512))
# subject_name = db.Column(db.String(512))
# valid_from = db.Column(db.String(512))
# valid_to = db.Column(db.String(512))

def add_update_weak_cert(id, file_name, file_hash , thumb_print, sign_algorithm,subject_name,valid_from,valid_to):
    if id:
        weakcert=WeakCert.query.filter_by(id=id).first()
        weakcert.file_name=file_name if file_name else weakcert.file_name
        weakcert.file_hash=file_name if file_hash else weakcert.file_hash
        weakcert.thumb_print=thumb_print if thumb_print else weakcert.thumb_print
        weakcert.public_key=sign_algorithm if sign_algorithm else weakcert.sign_algorithm
        weakcert.subject_name=subject_name if subject_name else weakcert.subject_name
        weakcert.valid_form=valid_from if valid_from else weakcert.valid_form
        weakcert.valid_to=valid_to if valid_to else weakcert.valid_to

        db.session.commit()
    else:
        current = WeakCert.query.filter_by(file_name=file_name,file_hash=file_hash).first()
        if current :
            return None
        data = dict(
            file_name=str(file_name),
            file_hash=str(file_hash),
            thumb_print=str(thumb_print),
            sign_algorithm=sign_algorithm,
            subject_name=str(subject_name),
            valid_form=str(valid_from),
            valid_to=str(valid_to)
        )
        df = WeakCert(**data)
        db.session.add(df)
        db.session.commit()

def delete_weak_cert(id, file_name, file_hash , thumb_print, sign_algorithm,subject_name,valid_from,valid_to):
    if id:
        weakcert=WeakCert.query.filter_by(id=id).first()

    db.session.delete(weakcert)
    db.session.commit()

def query_weak_cert(id, file_name, file_hash , thumb_print, sign_algorithm,subject_name,valid_from,valid_to):
    if id:
        return WeakCert.query.filter_by(id=id).first()

# HTTPValidationError(db.Model):
#     __tablename__ = 'http_validation_error'
#     id = db.Column(db.Integer, primary_key=True)
#
#     detail = db.Column(db.String(1024))
# ValidationError(db.Model):
#     __tablename__ = 'validation_error'
#     id = db.Column(db.Integer, primary_key=True)
#
#     loc = db.Column(db.String(512))
#     msg = db.Column(db.String(512))
#     type = db.Column(db.String(512))
def add_update_http_validation_error(id, detail,loc,msg,type):
    if id:
        http=HTTPValidationError.query.filter_by(id=id).first()
        http.detail=detail if detail else http.detail

        ve=ValidationError.query.filter_by(id=id).first()
        ve.loc=loc if loc else ve.loc
        ve.msg=msg if msg else ve.msg
        ve.type = type if type else ve.type

        db.session.commit()
    else:
        current =HTTPValidationError.query.filter_by(detail=detail).first()
        current1=ValidationError.query.filter_by(loc=loc,msg=msg,type=type).first()
        if current and current1:
            return None
        data = dict(
            detail=str(detail)
        )
        data0=dict(
            loc=str(loc),
            msg=str(msg),
            type=str(type)
        )
        df = HTTPValidationError(**data)
        df1=ValidationError(**data0)

        db.session.add(df)
        db.session.add(df1)
        db.session.commit()

def delete_weak_cert(id, file_name, file_hash , thumb_print, sign_algorithm,subject_name,valid_from,valid_to):
    if id:
        http=HTTPValidationError.query.filter_by(id=id).first()
        ve = ValidationError.query.filter_by(id=id).first()

    db.session.delete(http)
    db.session.delete(ve)
    db.session.commit()

def query_weak_cert(id, file_name, file_hash , thumb_print, sign_algorithm,subject_name,valid_from,valid_to):
    if id:
        return HTTPValidationError.query.filter_by(id=id).first(),ValidationError.query.filter_by(id=id).first()