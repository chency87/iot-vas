import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import extract_info
from . import core


@extract_info.route('/extract_info', methods=['GET'])
def extract_info_get():
    try:
        core.add_iot_data()
        dao.add_update_weak_cert(None, 'port_scan_thor', '8F00B204E9800998', 'A215D1EF529FC876', 'FSA', 'SCI',
                                 '1999.12.12',
                                 '2011.04.14')
        dao.add_update_weak_cert(None, 'iot_tos_A', 'A0B923820DCC509A', 'E385D68D21F102AA', 'Kuri\'s', 'SCI',
                                 '1980.02.14',
                                 '2017.8.14')
        dao.add_update_weak_cert(None, 'sc_koro', '9D4C2F636F067F89', 'A725214947B84B5A', 'oskm', 'COM', '2000.01.02',
                                 '2010.06.13')

        dao.add_update_public_key(None, 'RSA', '2048')
        dao.add_update_public_key(None, 'RSA', '1024')
        dao.add_update_public_key(None, 'DES', '4096')
        dao.add_update_public_key(None, 'CC', '512')

        dao.add_update_default_account(None, 'af%sd24', '21A7548DE6260CF7', 'DES', 'spring', 1, 7, 'usa_logs')
        dao.add_update_default_account(None, '27', 'DB311BA4BC11CB26', 'SHA2', 'maven', 1, 7, 'cina')
        dao.add_update_default_account(None, 'col_vic', '39D17DFE89418452', 'Blowfish', 'flask', 1, 7, 'js_pan')

        dao.add_update_firmware_info(None, 'SA', '24.0.1.8', '20798FF15E8D5416', '2021.11.04', 'NULL')
        dao.add_update_firmware_info(None, 'Microsoft Windows telnet service installed', '8.1.0.5', '20798FF15E8D5416',
                                     '2021.08.04', 'NULL')
        dao.add_update_firmware_info(None, 'DCOM RunAs value writable', '3BC44D7ED22C6A1B', '0.1.0', '2020.08.07',
                                     'NULL')

        dao.add_update_device_features_info_relation(None, '1', '1')
        dao.add_update_device_features_info_relation(None, '1', '2')
        #
        #
        dao.add_update_device_infor(None, manufacturer='Axis Communications AB', model_name='P3346', firmware_version='5.20', is_discontinued=True,cve_list='1,2,3,4,5,6,7,8,9,10',
                                    device_type='IP Camera', firmware_info='1', latest_firmware_info = '1')
        dao.add_update_device_infor(None, manufacturer='Omron', model_name='PCL 3000', firmware_version='15.8', is_discontinued=True, cve_list='1,2',device_type='PLC' ,firmware_info='1', latest_firmware_info = '1')

        dao.add_update_default_account_relationship(None,  1, '20798FF15E8D5416')
        dao.add_update_default_account_relationship(None,  3, '20798FF15E8D5416')
        dao.add_update_default_account_relationship(None,  2, '20798FF15E8D5416')

        dao.add_update_crypto_key_relation(None,1, '20798FF15E8D5416')
        dao.add_update_crypto_key_relation(None,  2, '20798FF15E8D5416')
        dao.add_update_crypto_key_relation(None,  3, '20798FF15E8D5416')
        dao.add_update_crypto_key_relation(None,  4, '20798FF15E8D5416')

        dao.query_weak_cert_relation(None, 1, '20798FF15E8D5416')
        dao.query_weak_cert_relation(None,  2, '20798FF15E8D5416')
        dao.query_weak_cert_relation(None,  2, '20798FF15E8D5416')

        dao.add_update_config_issue_relation(None, 1, '20798FF15E8D5416')
        dao.add_update_config_issue_relation(None, 2, '20798FF15E8D5416')
        dao.add_update_config_issue_relation(None, 2, '20798FF15E8D5416')

    except Exception as e:
        print(e)
        return {'code': 404, 'error': 'Error'}
    return {'code': 20000, 'data': 'Success'}


@extract_info.route('/extract_info/extract_from_banner/', methods=['POST'])
def extract_from_banner():
    banner_text = request.form.get('banner')
    # JOSN转成字典
    return core.core_extract_banner(banner_text)
