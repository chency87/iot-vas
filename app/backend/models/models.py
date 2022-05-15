from datetime import datetime
import json


from app.backend.database.database import db




class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(1024))
    task_name = db.Column(db.String(240))
    task_desc = db.Column(db.Text)
    task_engine = db.Column(db.String(240))
    task_trigger_type = db.Column(db.String(240))
    task_cron = db.Column(db.String(240))
    status = db.Column(db.Boolean)
    exe_time = db.Column(db.DateTime, default=datetime.now)
    cmd = db.Column(db.String(1024))
    stdout = db.Column(db.Text)

    def __repr__(self):
        return "{id:'%s', task_id:'%s', task_name:'%s',task_desc:'%s', task_engine:'%s', task_trigger_type:'%s', task_cron:'%s', status:'%s', exe_time:'%s', cmd:'%s', stdout:'%s' }" % (
            self.id,
            self.task_id,
            self.task_name,
            self.task_desc,
            self.task_engine,
            self.task_trigger_type,
            self.task_cron,
            self.status,            
            self.exe_time,
            self.cmd,
            self.stdout
        )

    def to_json(self):
        json_post = {
            'id': self.id,
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_desc': self.task_desc,
            'task_engine': self.task_engine,
            'task_trigger_type': self.task_trigger_type,
            'task_cron': self.task_cron,
            'status': self.status,
            'exe_time': self.exe_time,
            'cmd': self.cmd,
            'stdout': self.stdout
        }
        return json_post


class OpterationLog(db.Model):
    __tablename__ = 'opt_log'
    id = db.Column(db.Integer, primary_key=True)
    opt_ip = db.Column(db.String(16))
    opt_user = db.Column(db.String(200))
    opt_browser = db.Column(db.Text)
    opt_event = db.Column(db.String(200))
    opt_result = db.Column(db.String(16))
    opt_time = db.Column(db.DateTime, default=datetime.now)
    opt_detail = db.Column(db.Text)
    
    def to_json(self):
        json_post = {
            'id': self.id,
            'opt_ip': self.opt_ip,
            'opt_user': self.opt_user,
            'opt_browser': self.opt_browser,
            'opt_event': self.opt_event,
            'opt_time': self.opt_time,
            'opt_result': self.opt_result,
            'opt_detail': self.opt_detail,
        }
        return json_post

    

class PortInfo(db.Model):
    __tablename__ = 'port_info'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    port =  db.Column(db.Integer)
    protocol = db.Column(db.String(32))
    description = db.Column(db.String(240))
    dict_id = db.Column(db.Integer, db.ForeignKey('port_dict.id'), nullable=False)


    def to_json(self):
        json_post = {
            'id': self.id,
            'name' : self.name,
            'port' : self.port,
            'protocol' : self.protocol,
            'description' : self.description,
            'dict_id' : self.dict_id
        }
        return json_post
    
class PortDictInfo(db.Model):
    __tablename__ = 'port_dict'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    ports = db.relationship('PortInfo', backref='port_dict', cascade='all, delete, delete-orphan')

    def __init__(self, name) -> None:
        self.name = name
    def to_json(self):
        port_info = [port.to_json() for port in self.ports]
        json_post = {
            'id': self.id,
            'name' : self.name,
            'ports' : port_info,
            
        }
        return json_post


class DeviceFingerprint(db.Model):
    __tablename__ = 'device'
    
    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.String(128))
    product_name =  db.Column(db.String(240))
    serial_number =  db.Column(db.String(240))
    device_type =  db.Column(db.String(240))
    product_code =  db.Column(db.String(240))
    revision =  db.Column(db.String(240))
    service =  db.Column(db.String(240))
    protocol =  db.Column(db.String(240))
    device_ip = db.Column(db.String(64))


    def to_json(self):       
        json_post = {
            'id': self.id,
            'vendor' : self.vendor,
            'product_name' : self.product_name,
            'serial_number' : self.serial_number,
            'device_type' : self.device_type,
            'product_code' : self.product_code,
            'revision' : self.revision,
            'device_ip' : self.device_ip,
            'service' : self.service,
            'protocol' : self.protocol,            
        }
        return json_post



