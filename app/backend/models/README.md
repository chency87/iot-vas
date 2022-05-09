### Introduction

models 主要是定义数据库表信息，当我们需要创建一个表时，可以通过如下形式来定义表结构：
其中，__tablename__ 对应数据库中存储的表结构
其他，如主键id，等column name 自行定义，注意每个column的数据类型（String/Integer/Boolean）

大家在创建自己的每一个表的时候，要思考一下各个表之间的关系，1对1、1对多，多对一等等，根据具体情况来定义表结构，主键等信息。

我发给大家的demo中，所有主键均加了个ID，这个大家根据实际情况进行修改调整。

```
class DeviceInfo(db.Model):
    __tablename__ = 'device_info'
    id = db.Column(db.Integer, primary_key=True)
    manufacturer = db.Column(db.String(1024))
    model_name = db.Column(db.String(1024))
    firmware_version = db.Column(db.String(256))
    is_discontinued = db.Column(db.Boolean)
    cve_list = db.Column(db.String(1024)) # List of CVES, refer to Vulnerability
    device_type = db.Column(db.String(256))
    firmware_info = db.Column(db.String(256)) # List of Device firmware information, refer to firmwareInfo
    latest_firmware_info = db.Column(db.Integer) # Last Device firmware information, refer to firmwareInfo

    def to_json(self):
        json_post = {
            'id': self.id,
            'manufacturer': self.manufacturer,
            'model_name': self.model_name,
            'firmware_version': self.firmware_version,
            'is_discontinued': self.is_discontinued,
            'cve_list': self.cve_list,
            'device_type': self.device_type,
            'firmware_info': self.firmware_info,
            'latest_firmware_info': self.latest_firmware_info
        }
        return json_post


```