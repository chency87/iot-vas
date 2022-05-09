
from tinydb import TinyDB, where, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

from collections import namedtuple
import os

Port = namedtuple("Port", ["name", "port", "protocol", "description"])

__BASE_PATH__ = os.path.dirname(os.path.abspath(__file__))
__DATABASE_PATH__ = os.path.join(__BASE_PATH__, 'ports.json')
__DB__ = TinyDB(__DATABASE_PATH__, storage=CachingMiddleware(JSONStorage))


def get_port_info_by_port(port, like = False):
    # print(__DATABASE_PATH__)

    where_field = 'port'

    if like:
        ports = __DB__.search(where(where_field).search(str(port)))
    else:
        ports = __DB__.search(where(where_field) == str(port))
    try:
        return ports[0]['name']  # flake8: noqa (F812)
    except:
        return None
def get_port_info_by_name(name, like = False):
    where_field = 'name'
    if like:
        ports = __DB__.search(where(where_field).search(name))
    else:
        ports = __DB__.search(where(where_field) == name)
    try:
        return ports[0]['name']  # flake8: noqa (F812)
    except:
        return None
def get_all_port_info():
    try:
        return __DB__.all()
    except:
        return None
def GetPortInfo(port, like=False):
    """
    判断端口服务，传入参数为 字符串类型的数字
    返回服务名称  'http'，没有则返回  '检测失效'
    """
    
    where_field = "port" if port.isdigit() else "name"
    # print(where_field)
    # print('---' * 50)
    if like:
        ports = __DB__.search(where(where_field).search(port))
    else:
        ports = __DB__.search(where(where_field) == port)
    try:
        return ports[0]['name']  # flake8: noqa (F812)
    except:
        return None


from app.backend.models.models import PortInfo
from app.backend.database.database import db
from app.backend import error

def get_all_port_by_paginate(page, per_page):
    return PortInfo.query.paginate(page = page, per_page = per_page, error_out = False)

def add_port_info(id, name, port, protocol, description):
    if id:
        portinfo = PortInfo.query.filter_by(id=id).first()
        portinfo.name = name if name else portinfo.name
        portinfo.port = port if port else portinfo.port
        portinfo.protocol = protocol if protocol else portinfo.protocol
        portinfo.description = description if description else portinfo.description
        db.session.commit()
        return portinfo
    else:
        if port is None or name is None:
            return error.INVALID_INPUT_422
        portinfo = PortInfo.query.filter_by(port=port).first()
        if portinfo is not None:
            return error.ALREADY_EXIST
        portinfo = PortInfo(name = name, port = port,protocol = protocol,description = description)
        db.session.add(portinfo)
        db.session.commit()
        return portinfo
    
def del_port_info_by_id(id):
    if id:
        PortInfo.query.filter_by(id=id).delete()
        db.session.commit()

