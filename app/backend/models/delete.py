from app.backend.models.firmware_models import *

def CryptoKey_delete(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        cryptokey = CryptoKey.query.filter_by(id=id).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif file_name:
        cryptokey = CryptoKey.query.filter_by(file_name=file_name).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif file_hash:
        cryptokey = CryptoKey.query.filter_by(file_hash=file_hash).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif pem_type:
        cryptokey = CryptoKey.query.filter_by(pem_type=pem_type).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif algorithm:
        cryptokey = CryptoKey.query.filter_by(algorithm=algorithm).first()
        db.session.delete(cryptokey)
        db.session.commit()
    elif bits:
        cryptokey = CryptoKey.query.filter_by(bits=bits).first()
        db.session.delete(cryptokey)
        db.session.commit()
