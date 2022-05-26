
import bdb

from app.backend.models.firmware_models import *

# CryptoKey
from app.backend.models.user import User



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
        vulnerability.cvss=int(cvss) if cvss else vulnerability.cvss

        firminfor=FirmwareInfo.query.filter_by(id=id).first()
        firminfor.name=name if name else firminfor.name
        firminfor.version=version if version else firminfor.version
        firminfor.sha2=sha2 if sha2 else firminfor.sha2
        firminfor.release_date=release_date if release_date else firminfor.release_date
        firminfor.download_url=download_url if download_url else firminfor.download_url

        db.session.commit()
    else:
        data = dict(
            manufacturer=str(manufacturer),
            model_name=str(model_name),
            firmware_version=str(firmware_version),
            is_discontinued=str(is_discontinued),
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


def use_report1(listx):
    for index in range(len(listx)):
        ip = list(listx[index].keys())[0]
        os = listx[index][ip].get("os", "null")
        vendor = listx[index][ip].get("vendor", "null")
        model_name = listx[index][ip].get('model_name', '')
        firmware_version = listx[index][ip].get('firmware_version', '')
        is_discontinued = listx[index][ip].get('is_discontinued', '')
        cve_list = list(listx[index][ip].keys())[5]
        cve_id = []
        cvss = []
        for i in range(len(listx[index][ip][cve_list])):
            cve_id.append(listx[index][ip][cve_list].get('cve_id', ''))
            cvss.append(listx[index][ip][cve_list].get('cvss', ''))
        device_type = listx[index][ip].get('device_type', '')

        firmware_infor = list(listx[index][ip].keys())[7]
        firmware_infor_name = listx[index][ip][firmware_infor].get('name', '')
        firmware_infor_version = listx[index][ip][firmware_infor].get('version', '')
        firmware_infor_sha2 = listx[index][ip][firmware_infor].get('sha2', '')
        str_cve_id = ''
        str_cvss = ''
        for i in range(len(cve_id)):
            str_cvss = str_cvss + cvss[i] + ','
            str_cve_id = str_cve_id + cve_id[i] + ','

        tcp = list(listx[index][ip].keys())[8]
        udp = list(listx[index][ip].keys())[9]

        tcp_port = []
        tcp_service = []
        udp_port = []
        udp_service = []
        snmp_sysdescr_list = []

        for i in range(len(listx[index][ip][tcp])):
            tcp_port.append(listx[index][ip][tcp][i].get('port', ''))
            tcp_service.append(listx[index][ip][tcp][i].get('service', ''))
            snmp_sysdescr_list.append(listx[index][ip][tcp][i].get('snmp_sysdescr', ''))
        for i in range(len(listx[index][ip][udp])):
            udp_port.append(listx[index][ip][udp][i].get('port', ''))
            udp_service.append(listx[index][ip][udp][i].get('service', ''))
            snmp_sysdescr_list.append(listx[index][ip][udp][i].get('snmp-sysdescr', ''))
        snmp_sysdescr = ''
        for i in range(len(snmp_sysdescr_list)):
            snmp_sysdescr = snmp_sysdescr + snmp_sysdescr_list[i]

        snmp_sysdescr=listx[index][ip].get('snmp_sysdescr','')
        snmp_sysoid=listx[index][ip].get('snmp_sysoid','')
        ftp_banner=listx[index][ip].get('ftp_banner','')
        telnet_banner=listx[index][ip].get('telnet_banner','')
        hostname=listx[index][ip].get('hostname','')
        http_response=listx[index][ip].get('http_response','')
        https_response=listx[index][ip].get('https_response','')
        upnp_response=listx[index][ip].get('upnp_response','')
        nic_mac=listx[index][ip].get('nic_mac','')

        add_update_device_infor(None, vendor, model_name, firmware_version, is_discontinued, '', device_type, '', 0,
                                str_cve_id, str_cvss, firmware_infor_name, firmware_infor_version, firmware_infor_sha2,
                                '', '')
        # add_update_device_infor(None,vendor,model_name,firmware_version,is_discontinued,None,device_type,None,None,str_cve_id,str_cvss,firmware_infor_name,firmware_infor_version,firmware_infor_sha2,None,None)
        add_update_device_features(None,snmp_sysdescr,snmp_sysoid,ftp_banner,telnet_banner,hostname,http_response,https_response,upnp_response,nic_mac)
