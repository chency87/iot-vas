from app.backend.database.database import db

from app.backend.models.models import DeviceFingerprint

from app.backend.models.firmware_models import DeviceFeatures

def add_update_device(id, vendor, product_name,serial_number,device_type, product_code,revision,service,protocol,device_ip ):
    if id:
        device = DeviceFingerprint.query.filter_by(id=id).first()
        device.vendor = vendor if vendor else device.vendor
        device.product_name = product_name if vendor else device.product_name
        device.serial_number = serial_number if serial_number else device.serial_number
        device.device_type = device_type if device_type else device.device_type
        device.product_code = product_code if product_code else device.product_code
        device.revision = revision if revision else device.revision
        device.service = service if service else device.service
        device.protocol = protocol if protocol else device.protocol
        device.device_ip = device_ip if device_ip else device.device_ip
        db.session.commit()
    else:
        current = DeviceFingerprint.query.filter_by(vendor = vendor, product_name = product_name, serial_number = serial_number).first()
        if current:
            return None
        data = dict(
            vendor = str(vendor), 
            product_name = str(product_name), 
            serial_number = str(serial_number), 
            device_type= str(device_type), 
            product_code = str(product_code), 
            revision = str(revision), 
            service = str(service), 
            protocol = str(protocol), 
            device_ip = str(device_ip)
        )
        df = DeviceFingerprint(**data)

        db.session.add(df)
        db.session.commit()


def del_device_by_id(id):
    
    if id:       
        
        DeviceFingerprint.query.filter_by(id=id).delete()
        db.session.commit()

def get_all_device_by_paginate(page, per_page):
    return DeviceFingerprint.query.paginate(page = page, per_page = per_page, error_out = False)
    # return DeviceFingerprint.query.paginate(page = page, per_page = per_page, error_out = False)

def search_device_info(data):
    # DeviceFeatures.query.

    pass
