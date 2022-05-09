#!/usr/bin/python
# -*- coding: utf-8 -*-

import functools
import logging

from flask import request

from app.backend import error
from app.conf.auth import jwt

class Role:
    sa = 0
    admin = 1
    user = 2

def permission(arg):
    def check_permissions(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            token = request.cookies.get('access_token')
            data = jwt.loads(token)

            if int(data["admin"]) == Role.sa or int(data["admin"]) == Role.admin or int(data['admin']) == arg:
                print('have permission')
                return f(*args, **kwargs)
            else:
                return error.PERMISSIONDENY
        return decorated

    return check_permissions
