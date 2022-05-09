from werkzeug.exceptions import HTTPException
from flask import request
import json
import typing as t


class APIException(HTTPException):
    code = 500
    msg = 'Sorry, We made a mistake!'
    error_code = 999

    def __init__(self, msg=None, code=None, error_code=None, headers=None):
        if code:
            self.code = code
        if error_code:
            self.error_code = error_code
        if msg:
            self.msg = msg
        super(APIException, self).__init__(msg, None)

    def get_body(self, environ=None, scope: t.Optional[dict] = None,):
        body = dict(
            msg=self.msg,
            error_code=self.error_code,
            request=request.method + ' ' + self.get_url_no_param()
        )
        text = json.dumps(body)
        return text

    def get_headers(self, environ=None, scope = None,):
        """Get a list of headers."""
        return [('Content-Type', 'application/json')]

    @staticmethod
    def get_url_no_param():
        full_path = str(request.full_path)
        main_path = full_path.split('?')
        return main_path[0]

class Success(APIException):
    code = 201
    msg = 'ok'
    error_code = 0


class DeleteSuccess(APIException):
    code = 202
    msg = 'delete ok'
    error_code = 1


class UpdateSuccess(APIException):
    code = 200
    msg = 'update ok'
    error_code = 2
    def __init__(self, msg=None):
        self.msg = msg
    


class ServerError(APIException):
    code = 500
    msg = 'sorry, we made a mistake!'
    error_code = 999


class ParameterException(APIException):
    code = 400
    msg = 'invalid parameter'
    error_code = 1000


class NotFound(APIException):
    code = 404
    msg = 'the resource are not found'
    error_code = 1001


class AuthFailed(APIException):
    code = 401
    msg = 'authorization failed'
    error_code = 1005


class Forbidden(APIException):
    code = 403
    error_code = 1004
    msg = 'forbidden, not in scope'
