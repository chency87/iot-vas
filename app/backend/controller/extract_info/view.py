import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import extract_info

@extract_info.route('/extract_info/details', methods=['GET'])
def show_details():
    try:
        #测试1
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,1,2,'test1')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test2')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,1,3,'test3')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test4')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test5')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test6')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test7')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test8')
        # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test9')
        #
        # dao.add_update_risk_summary(None,'test0','eqw0','wqee0','qweqwe0')
        # dao.add_update_risk_summary(None,'test1','eqw1','wqee1','qweqwe1')
        # dao.add_update_risk_summary(None,'test2','eqw2','wqee2','qweqwe2')
        # dao.add_update_vulnerable_component(None,'test1','test2','test3','test4',1)
        # dao.add_update_vulnerable_component(None,'test2','test3','test4','test5',2)
        # dao.add_update_vulnerable_component(None,'test3','test4','test5','test6',3)

        #测试2
        # dao.add_update_default_account_relationship(None,2,'test')
        # dao.add_update_default_account_relationship(None,3,'test1')
        # dao.add_update_default_account_relationship(None,2,'test2')
        # dao.add_update_default_account_relationship(None,3,'test3')
        # dao.add_update_default_account_relationship(None,3,'test4')
        #
        # dao.add_update_default_account(None,'test0','test1','test2','test3',1,2,'test4')
        # dao.add_update_default_account(None,'test1','test2','test3','test4',2,3,'test5')
        # dao.add_update_default_account(None,'test2','test3','test4','test5',3,2,'test6')
        # dao.add_update_default_account(None,'test3','test4','test5','test6',2,3,'test7')
        # dao.add_update_default_account(None,'test4','test5','test6','test7',3,2,'test8')
        # dao.add_update_default_account(None,'test5','test6','test7','test8',2,3,'test9')

        #测试3
        # dao.add_update_crypto_key(None,'file_name1','filehash1','pem_type_1','sha1',10)
        # dao.add_update_crypto_key(None,'file_name2','filehash2','pem_type_2','sha2',20)
        # dao.add_update_crypto_key(None,'file_name3','filehash3','pem_type_3','sha3',30)
        # dao.add_update_crypto_key(None,'file_name4','filehash4','pem_type_4','sha4',40)
        # dao.add_update_crypto_key(None,'file_name5','filehash5','pem_type_5','sha5',50)
        # dao.add_update_crypto_key(None,'file_name6','filehash6','pem_type_6','sha6',60)
        # dao.add_update_crypto_key(None,'file_name7','filehash7','pem_type_7','sha7',70)
        # dao.add_update_crypto_key(None,'file_name8','filehash8','pem_type_8','sha8',80)
        #
        # dao.add_update_crypto_key_relation(None,1,'test1')
        # dao.add_update_crypto_key_relation(None,2,'test2')
        # dao.add_update_crypto_key_relation(None,3,'test3')
        # dao.add_update_crypto_key_relation(None,4,'test4')
        # dao.add_update_crypto_key_relation(None,5,'test5')
        # dao.add_update_crypto_key_relation(None,6,'test6')
        # dao.add_update_crypto_key_relation(None,7,'test7')
        # dao.add_update_crypto_key_relation(None,8,'test8')

        #测试4
        # dao.add_update_expired_cert(None,'file1','test1','thumb1',1,'jjkk','from1','to1','sha1',10)
        # dao.add_update_expired_cert(None,'file2','test2','thumb2',2,'jjkk','from2','to2','sha2',20)
        # dao.add_update_expired_cert(None,'file3','test3','thumb3',3,'jjkk','from3','to3','sha3',30)
        # dao.add_update_expired_cert(None,'file4','test4','thumb4',4,'jjkk','from4','to4','sha4',40)
        # dao.add_update_expired_cert(None,'file5','test5','thumb5',5,'jjkk','from5','to5','sha5',50)
        # dao.add_update_expired_cert(None,'file6','test6','thumb6',6,'jjkk','from6','to6','sha6',60)
        # dao.add_update_expired_cert(None,'file7','test7','thumb7',7,'jjkk','from7','to7','sha7',70)
        # dao.add_update_expired_cert(None,'file8','test8','thumb8',8,'jjkk','from8','to8','sha8',80)
        #
        # dao.add_update_expired_cert_relation(None,1,'test1')
        # dao.add_update_expired_cert_relation(None,2,'test2')
        # dao.add_update_expired_cert_relation(None,3,'test3')
        # dao.add_update_expired_cert_relation(None,4,'test4')
        # dao.add_update_expired_cert_relation(None,5,'test5')
        # dao.add_update_expired_cert_relation(None,6,'test6')
        # dao.add_update_expired_cert_relation(None,7,'test7')
        # dao.add_update_expired_cert_relation(None,8,'test8')

        #测试5
        # dao.add_update_weak_cert(None,'file1','test1','thumb1','sadas','jjkk','from1','to1')
        # dao.add_update_weak_cert(None,'file2','test2','thumb2','sadas','jjkk','from2','to2')
        # dao.add_update_weak_cert(None,'file3','test3','thumb3','sadas','jjkk','from3','to3')
        # dao.add_update_weak_cert(None,'file4','test4','thumb4','sadas','jjkk','from4','to4')
        # dao.add_update_weak_cert(None,'file5','test5','thumb5','sadas','jjkk','from5','to5')
        # dao.add_update_weak_cert(None,'file6','test6','thumb6','sadas','jjkk','from6','to6')
        # dao.add_update_weak_cert(None,'file7','test7','thumb7','sadas','jjkk','from7','to7')
        # dao.add_update_weak_cert(None,'file8','test8','thumb8','sadas','jjkk','from8','to8')
        #
        # dao.add_update_weak_cert_relation(None,1,'test1')
        # dao.add_update_weak_cert_relation(None,2,'test2')
        # dao.add_update_weak_cert_relation(None,3,'test3')
        # dao.add_update_weak_cert_relation(None,4,'test4')
        # dao.add_update_weak_cert_relation(None,5,'test5')
        # dao.add_update_weak_cert_relation(None,6,'test6')
        # dao.add_update_weak_cert_relation(None,7,'test7')
        # dao.add_update_weak_cert_relation(None,8,'test8')

        #测试6
        # dao.add_update_config_issue(None,'HTTP','HTTP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'HTTPS','HTTPS.config','issues','suggestions')
        # dao.add_update_config_issue(None,'SMTP','SMTP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'POP3','POP3.config','issues','suggestions')
        # dao.add_update_config_issue(None,'IMAP','IMAP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'FTP','FTP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'DNS','DNS.config','issues','suggestions')
        # dao.add_update_config_issue(None,'LDAP','LDAP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'SSL','SSL.config','issues','suggestions')
        # dao.add_update_config_issue(None,'TLS','TLS.config','issues','suggestions')
        # dao.add_update_config_issue(None,'SSH','SSH.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Telnet','Telnet.config','issues','suggestions')
        # dao.add_update_config_issue(None,'RDP','RDP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'SMB','SMB.config','issues','suggestions')
        # dao.add_update_config_issue(None,'SNMP','SNMP.config','issues','suggestions')
        # dao.add_update_config_issue(None,'MSSQL','MSSQL.config','issues','suggestions')
        # dao.add_update_config_issue(None,'MYSQL','MYSQL.config','issues','suggestions')
        # dao.add_update_config_issue(None,'ORACLE','ORACLE.config','issues','suggestions')
        # dao.add_update_config_issue(None,'PostgreSQL','PostgreSQL.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Oracle','Oracle.config','issues','suggestions')
        # dao.add_update_config_issue(None,'MongoDB','MongoDB.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Redis','Redis.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Memcached','Memcached.config','issues','suggestions')
        # dao.add_update_config_issue(None,'RabbitMQ','RabbitMQ.config','issues','suggestions')
        # dao.add_update_config_issue(None,'ActiveMQ','ActiveMQ.config','issues','suggestions')
        # dao.add_update_config_issue(None,'OpenStack','OpenStack.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Apache','Apache.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Tomcat','Tomcat.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Nginx','Nginx.config','issues','suggestions')
        # dao.add_update_config_issue(None,'IIS','IIS.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Weblogic','Weblogic.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Websphere','Websphere.config','issues','suggestions')
        # dao.add_update_config_issue(None,'JBoss','JBoss.config','issues','suggestions')
        # dao.add_update_config_issue(None,'Tomcat','Tomcat.config','issues','suggestions')
        # dao.add_update_config_issue(None,'GlassFish','GlassFish.config','issues','suggestions')
        #
        #
        # dao.add_update_config_issue_relation(None,1,'test1')
        # dao.add_update_config_issue_relation(None,2,'test2')
        # dao.add_update_config_issue_relation(None,3,'test3')
        # dao.add_update_config_issue_relation(None,4,'test4')
        # dao.add_update_config_issue_relation(None,5,'test5')
        # dao.add_update_config_issue_relation(None,6,'test6')
        # dao.add_update_config_issue_relation(None,7,'test7')
        # dao.add_update_config_issue_relation(None,8,'test8')
        # dao.add_update_config_issue_relation(None,9,'test9')
        # dao.add_update_config_issue_relation(None,10,'test10')
        # dao.add_update_config_issue_relation(None,11,'test11')
        # dao.add_update_config_issue_relation(None,12,'test12')
        # dao.add_update_config_issue_relation(None,13,'test13')
        # dao.add_update_config_issue_relation(None,14,'test14')
        pass

    except Exception as e:
        print(e)
   # add.CryptoKey_add_update('1','1','1','1',1)
    print("helloworld")
    return "extract_info/details"

@extract_info.route('/extract_info/extract_from_banner/', methods=['POST'])
def extract_from_banner():
    banner_text = request.form.get('banner')
    #JOSN转成字典

    dict1 = json.loads(banner_text)

    print(dict1)

    key = ""
    value = ""

    #得到不空的key-value
    for i in dict1:
        if(dict1[i] !=""):
            key = i
            value = dict1[i]

    if(key == ""):
        return "没有可以提取的信息"

    #查询DeviceFeatures表中是否有该设备


    # banner_list = banner_text.split()
    # print(banner_list)
    #
    # manufacturer = banner_list[0]
    # model_name = banner_list[1]
    # firmware_version = ""
    # for i in range(2, len(banner_list)):
    #     banner_list[i] = banner_list[i]+" "
    #     firmware_version += banner_list[i]
    # #拆解成DeviceInfo中三个属性
    # print(manufacturer, model_name, firmware_version)
    # try:
    #     device_info2 = dao.query_device_infor(None, manufacturer, model_name, firmware_version, None, None, None, None,
    #                                           None, None, None, None, None, None, None, None)
    # except Exception as e:
    #     dao.add_update_device_infor(None, manufacturer, model_name, firmware_version, None, None, None, None, None,
    #                                 None, None, None, None, None, None, None, None)
    #     print(e)
    #return jsonify({"manfacturer": manufacturer, "model": model_name, "firmware_version": firmware_version})
    # class DeviceFeatures(db.Model):
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
        if(key == "snmp_sysdescr"):
            device_info1 = dao.query_all_device_features(None, str(value), None, None, None, None, None, None, None, None)
        elif(key == "snmp_sysoid"):
            device_info1 = dao.query_all_device_features(None, None, str(value), None, None, None, None, None, None, None)
        elif(key == "ftp_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, str(value), None, None, None, None, None, None)
        elif(key == "telnet_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, None, str(value), None, None, None, None, None)
        elif(key == "hostname"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, str(value), None, None, None, None)
        elif(key == "http_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, str(value), None, None, None)
        elif(key == "https_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, str(value), None, None)
        elif(key == "upnp_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, str(value), None)
        elif(key == "nic_mac"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, None, str(value))
        snmp_sysdescr = device_info1.snmp_sysdescr
        snmp_sysoid = device_info1.snmp_sysoid
        ftp_banner = device_info1.ftp_banner
        telnet_banner = device_info1.telnet_banner
        hostname = device_info1.hostname
        http_response = device_info1.http_response
        https_response = device_info1.https_response
        upnp_response = device_info1.upnp_response
        nic_mac = device_info1.nic_mac
    except Exception as e:
        return "在数据库中找不到该数据"
        print(e)

    if(device_info1 is None):
        return "在数据库中找不到该数据"

    id = device_info1.id

    if(id is None):
        return "该数据ID不存在"

    dict = {
        "snmp_sysdescr": snmp_sysdescr,
        "snmp_sysoid": snmp_sysoid,
        "ftp_banner": ftp_banner,
        "telnet_banner": telnet_banner,
        "hostname": hostname,
        "http_response": http_response,
        "https_response": https_response,
        "upnp_response": upnp_response,
        "nic_mac": nic_mac

    }


    id_device_features = []
    for i in range(0, len(device_info1)):
        id_device_features.append(device_info1[i].id)

    for i in range(0, len(id_device_features)):
        device_temp_info = dao.query_device_features_info_relation(None, id_device_features[i], None)
        id_device_info = device_temp_info.id_DeviceInfo
        ###

    device_info2 = []

    try:
        nic_mac = device_info1.nic_mac
        print(nic_mac)
    except Exception as e:
        print(e)




