from . import setting

from marshmallow import fields
from werkzeug.wrappers import response

from flask import json, render_template,request, jsonify

from flask_login import current_user, login_required

from app.backend.handlers import port_handler
from app.backend.schema.schemas import UserSchema
# from .core import PortDictMana

from app.backend.handlers.settings.core import PortDictMana, PortInfoMana




@setting.route('/settings/dictmanage.html', methods=['GET'])
def show_port_dict_page():
    data = UserSchema().dump(current_user)
    port_dicts = PortDictMana.get_all_port_dict()
    
    return render_template('pages/settings/portdictmanage.html', title="数据字典管理", header="终端端口-服务字典管理", form = data, port_dicts = port_dicts)
    # return render_template('pages/settings/dictmanage.html', title="数据字典管理", header="终端端口-服务字典管理", form = data)

# @setting.route('/settings/allports', methods=['GET'])
# def show_all_port():
#     response = {
#         'data' : port_handler.get_all_port_info()
#     }
#     return response

@setting.route('/settings/dicts', methods=['POST'])
def add_update_port_dict22():
    response = {
        'status' : -1
    }
    try:
        # pdm = PortDictMana()
        data = request.get_json(force=True)
        print(data)
        id = int(data['id']) if data['id'] else None
        PortDictMana.add_update_port_dict(id,data['name'])
        response['status'] = 200
        response['msg'] = "Add Success"
        response['result'] = True
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)

@setting.route('/settings/dicts', methods = ['DELETE'])
def del_port_dict_info():
    response = {'status' : -1 }
    try:
        id = int(request.args.get('id'))
        PortDictMana.delete_port_dict_by_id(id)
        response['status'] = 200
        response['msg'] = 'DELETE SUCCESS'
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)



@setting.route('/settings/ports', methods = ['GET'])
def show_port_info_by_dict_id():
    response = {
        'status' : -1,
    }
    try:
        id = int(request.args.get('id'))
        ports = PortInfoMana.get_all_port_by_dict_id(id)
        dic = []
        for item in ports:
            dic.append(item.to_json())
        response['recordsTotal'] = len(dic)
        response['recordsFiltered'] = len(dic)
        response['data'] = dic
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)



# @setting.route('/settings/ports', methods = ['GET'])
# def show_port_info():
#     response = {
#         'status' : -1,
#     }
#     try:
#         start = int(request.args.get('start'))
#         length = int(request.args.get('length'))
#         page = start / length  + 1
#         if start is not None and length is not None:
#             ports = port_handler.get_all_port_by_paginate(page, length)
#             dic = []
#             for item in ports.items:
#                 dic.append(item.to_json())
#             response['recordsTotal'] = ports.total
#             response['recordsFiltered'] = ports.total
#             response['data'] = dic
#     except Exception as e:
#         response['msg'] = str(e)
#     return jsonify(response)

@setting.route('/settings/ports', methods = ['POST'])
def add_port_info():
    response = {'status': '-1'}
    try:
        data = request.get_json(force=True)
        PortInfoMana.add_port_info(data['id'],data['name'],data['port'],data['protocol'],data['description'], data['dict_id'])
        # port_handler.add_port_info(data['id'],data['name'],data['port'],data['protocol'],data['description'])

        response['status'] = 200
        response['msg'] = "Add Success"
        response['result'] = True
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)

@setting.route('/settings/ports', methods = ['DELETE'])
def del_port_info():
    response = {'status' : -1 }
    try:
        id = int(request.args.get('id'))
        PortInfoMana.del_port_info_by_id(id)
        # port_handler.del_port_info_by_id(id)
        response['status'] = 200
        response['msg'] = 'DELETE SUCCESS'
    except Exception as e:
        response['msg'] = str(e)
    return jsonify(response)


