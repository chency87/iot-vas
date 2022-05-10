from app.backend.models.firmware_models import *

def CryptoKey_search(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        return CryptoKey.query.filter_by(id=id).first()
    elif file_name:
        return CryptoKey.query.filter_by(file_name=file_name).first()
    elif file_hash:
        return CryptoKey.query.filter_by(file_hash=file_hash).first()
    elif pem_type:
        return CryptoKey.query.filter_by(pem_type=pem_type).first()
    elif algorithm:
        return CryptoKey.query.filter_by(algorithm=algorithm).first()
    elif bits:
        return CryptoKey.query.filter_by(bits=bits).first()