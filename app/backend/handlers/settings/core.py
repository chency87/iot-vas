from os import pipe
from app.backend.models.models import PortInfo, PortDictInfo



from app.backend.database.database import db
from app.backend import error

class PortDictMana:
    @staticmethod
    def get_all_port_dict():
        return PortDictInfo.query.all()
    @staticmethod
    def add_update_port_dict(id, name):
        # print('you have been in the ' + __name__)
        if id:
            print('this id is not none ' * 25)
            port_dict = PortDictInfo.query.filter_by(id=id).first()
            port_dict.name = name if name else port_dict.name
            db.session.commit()
        else:
            if name is None:
                return error.INVALID_INPUT_422
            port_dict = PortDictInfo.query.filter_by(name=name).first()
            if port_dict is not None:
                return error.ALREADY_EXIST
            portDict = PortDictInfo(name=name)
            # print(' try to add dict ' * 50)
            db.session.add(portDict)
            db.session.commit()
        return name
    @staticmethod
    def delete_port_dict_by_id( id):
        if id:
            PortDictInfo.query.filter_by(id=id).delete()
            db.session.commit()

class PortInfoMana:
    @staticmethod
    def get_all_port_by_dict_id( dict_id):
        return PortInfo.query.filter_by(dict_id = dict_id).all()

    @staticmethod
    def get_all_port_by_paginate( page, per_page):
        return PortInfo.query.paginate(page = page, per_page = per_page, error_out = False)
    @staticmethod
    def add_port_info( id, name, port, protocol, description, dict_id):
        if id:
            portinfo = PortInfo.query.filter_by(id=id).first()
            portinfo.name = name if name else portinfo.name
            portinfo.port = port if port else portinfo.port
            portinfo.protocol = protocol if protocol else portinfo.protocol
            portinfo.description = description if description else portinfo.description
            portinfo.dict_id = dict_id if dict_id else portinfo.dict_id
            db.session.commit()
            return portinfo
        else:
            if port is None or name is None:
                return error.INVALID_INPUT_422
            portinfo = PortInfo.query.filter_by(port=port).first()
            if portinfo is not None:
                return error.ALREADY_EXIST
            portinfo = PortInfo(name = name, port = port,protocol = protocol,description = description, dict_id = dict_id)
            db.session.add(portinfo)
            db.session.commit()
            return portinfo
    @staticmethod
    def del_port_info_by_id( id):
        if id:
            PortInfo.query.filter_by(id=id).delete()
            db.session.commit()
