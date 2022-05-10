from app.backend.models.firmware_models import *

def CryptoKey_add_update(id, file_name, file_hash , pem_type, algorithm, bits):
    if id:
        cryptokey = CryptoKey.query.filter_by(id=id).first()
        cryptokey.file_name=file_name if file_name else cryptokey.file_name
        cryptokey.file_hash=file_hash if file_hash else cryptokey.file_hash
        cryptokey.pem_type=pem_type if pem_type else cryptokey.pem_type
        cryptokey.algorithm=algorithm if algorithm else cryptokey.algorithm
        cryptokey.bits=bits if bits else cryptokey.bits
        db.session.commit()
    else:
        current = CryptoKey.query.filter_by(file_name=file_name,file_hash=file_hash).first()
        if current:
            return None
        data = dict(
            file_name=str(file_name),
            file_hash=str(file_hash),
            pem_type=str(pem_type),
            algorithm=str(algorithm),
            bits=bits
        )
        df = CryptoKey(**data)

        db.session.add(df)
        db.session.commit()



# id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(512))
#     pwd_hash = db.Column(db.String(512))
#     hash_algorithm = db.Column(db.String(512)) #title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
#     shell = db.Column(db.String(512))
#     uid = db.Column(db.Integer)
#     gid = db.Column(db.Integer)
#     home_dir = db.Column(db.String(512))