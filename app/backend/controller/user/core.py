import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import user_blueprint

def login(username, password):
    if username == 'admin':
        # 管理员登录
        return jsonify(
            {"code": 20000, "data": {"token": "admin-token", "role": "admin"}}
        )
    else:
        # 普通用户登录
        # 首先去数据库查表
        user = dao.query_user(None, username, None, None, None, None)
        if user is None:
            return jsonify(
                {"code": 20001, "message": "用户不存在"}
            )
        else:
            if user.password == password:
                return jsonify(
                    {"code": 20000, "data": {"token": "admin-token", "role": "admin"}}
                )
            else:
                return jsonify(
                    {"code": 20002, "message": "密码错误"}
                )


