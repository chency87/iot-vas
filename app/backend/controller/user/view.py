import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import user_blueprint
from . import core

#为web而造
@user_blueprint.route('/login', methods=['POST'])
def login():
    #POST接收参数
    data = request.get_data(as_text=True)
    #print(data)
    data = json.loads(data)

    username = data['username']
    password = data['password']

    return core.login(username, password)




@user_blueprint.route('/user/logout', methods=['POST'])
def logout():
    return jsonify(
        {"code": 20000, "data": {"token": "admin-token", "role": "admin"}}
    )

@user_blueprint.route('/user/info', methods=['GET'])
def user_info():



    return jsonify(
         {"code":20000,"data":{"roles":["admin"],"introduction":"I am a super administrator","avatar":"https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif","name":"Super Admin"}}
    )

@user_blueprint.route('/user/table/list', methods=['GET'])
def table_list():
    return "???"
    return None




