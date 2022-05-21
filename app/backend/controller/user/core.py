import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import user_blueprint

def login(username, password):
    #查数据库表来判断用户名和密码是否正确
    user = dao.query_user(None, username, None,None,None,None)

    if user is None:
        return jsonify(
                {"code": 20001, "message": "用户不存在"}
            )
    elif user.password == password:
        if(user.user_role is None or user.user_role == "user"):
            return jsonify(
                {"code": 20000, "data": {"token": "user-token", "role": "user"}}
            )
        else:
            return jsonify(
                {"code": 20000, "data": {"token": "admin-token", "role": "admin"}}
            )
    else:
        return jsonify(
                {"code": 20002, "message": "密码错误"}
            )


