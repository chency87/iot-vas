import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import extract_info
from . import core

@extract_info.route('/extract_info', methods=['GET'])
def extract_info_get():
    try:
        core.add_iot_data()
    except Exception as e:
        print(e)
        return {'code':404,'error': 'Error'}
    return {'code':20000,'data': 'Success'}

@extract_info.route('/extract_info/extract_from_banner/', methods=['POST'])
def extract_from_banner():
    banner_text = request.form.get('banner')
    #JOSN转成字典
    return core.core_extract_banner(banner_text)







