import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import extract_info

# Python计算字符串或文件的MD5/SHA值
import hashlib

# 计算字符串的SHA 224值
def str(text, algorithm):
    algorithm.update(text.encode(encoding='UTF-8'))
    return algorithm.hexdigest()

def Str2Sha224(text):
    return str(text, hashlib.sha224())

# insert the right data into the database

# 1 ConfigIssue ConfigIssueRelation
# 2 ExpiredCert and ExpiredCertRelation
# 3 CryptoKey CryptoKeyRelation
# 4 DefaultAccount DefaultAccountRelationship

def addConfigIssue():
    #    firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo
    #    add the data to the Configissue and ConfigIssueRelation tables
    try:
        dao.add_update_config_issue(None, 'Telnet', '/etc/init.d/rcS', 'Result: telnet enabled in path',
                                    'Disable telnet in path and use SSH instead')
        dao.add_update_config_issue(None, 'Telnet', '/etc/init.d/rcS.v2.0', 'Result: telnet enabled in path',
                                    'Disable telnet in path and use SSH instead')
        dao.add_update_config_issue(None, 'SNMP', '/usr/local/etc/ippf/base/snmpd.conf',
                                    'Result: found e asy guessable snmp community string',
                                    'Change public/private community strings to another value')
    except Exception as e:
        print(e)

# 2 ExpiredCert and ExpiredCertRelation
def addExpiredCert():
    # 2 ExpiredCert and ExpiredCertRelation
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                '02faf3e291435468607857694df5e45b68851868', None,
                                'C=SE,O=AddTrust AB,OU=AddTrust External TTP Network,CN=AddTrust External CA Root',
                                '2000-05-30T10:48:38Z', '2020-05-30T10:48:38Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                'ccab0ea04c2301d6697bdd379fcd12eb24e3949d', None,
                                'C=SE,O=AddTrust AB,OU=AddTrust TTP Network,CN=AddTrust Class 1 CA Root',
                                '2000-05-30T10:38:31Z', '2020-05-30T10:38:31Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                '4d2378ec919539b5007f758f033b211ec54d8bcf', None,
                                'C=SE,O=AddTrust AB,OU=AddTrust TTP Network,CN=AddTrust Qualified CA Root',
                                '2000-05-30T10:44:50Z', '2020-05-30T10:44:50Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                '2ab628485e78fbf3ad9e7910dd6bdf99722c96e5', None,
                                'C=SE,O=AddTrust AB,OU=AddTrust TTP Network,CN=AddTrust Public CA Root',
                                '2000-05-30T10:41:50Z', '2020-05-30T10:41:50Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                'a9e9780814375888f20519b06d2b0d2b6016907d', None,
                                'C=US,O=GeoTrust Inc.,CN=GeoTrust Global CA 2', '2004-03-04T05:00:00Z',
                                '2019-03-04T05:00:00Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                '58119f0e128287ea50fdd987456f4f78dcfad6d4', None,
                                'C=US,ST=UT,L=Salt Lake City,O=The USERTRUST Network,OU=http://www.usertrust.com,CN=UTN - DATACorp SGC',
                                '1999-06-24T18:57:21Z', '2019-06-24T19:06:30Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                'd23209ad23d314232174e40d7f9d62139786633a', None,
                                'C=US,O=Equifax,OU=Equifax Secure Certificate Authority', '1998-08-22T16:41:51Z',
                                '2018-08-22T16:41:51Z', 'RSA', 1024)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                '0483ed3399ac3608058722edbc5e4600e3bef9d7', None,
                                'C=US,ST=UT,L=Salt Lake City,O=The USERTRUST Network,OU=http://www.usertrust.com,CN=UTN-USERFirst-Hardware',
                                '1999-07-09T18:10:42Z', '2019-07-09T18:19:22Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'nwsoc_RootCert.pem',
                                '4b5b840d5becdda4eb8a44a488db551bd68557c5b2e9811d473506aa28302d2b',
                                'b18d9d195669ba0f7829517566c25f422a277104', None,
                                'C=US,O=VeriSign, Inc.,OU=VeriSign Trust Network,OU=Terms of use at https://www.verisign.com/rpa (c)10,CN=VeriSign Class 3 International Server CA - G3',
                                '2010-02-08T00:00:00Z', '2020-02-07T23:59:59Z', 'RSA', 2048)
    dao.add_update_expired_cert(None, 'server.pem', 'e8944eba6be07e26aeefe15893c47b9ab93828d2000e60033cd5db61e93a8910',
                                'dfad9b22e5c8531314df3ab8b25258115af06af2', None,
                                'C=US,ST=CA,L=SJ,O=Cisco,OU=CDTG,CN=ut610n,emailAddress=ut610n@cdtg.cisco.com',
                                '2009-10-08T23:42:14Z', '2010-10-08T23:42:14Z', 'RSA', 1024)

def addCryptoKey():
    # 3 CryptoKey CryptoKeyRelation
    dao.add_update_crypto_key(None, 'key.pem', '5c26251e4db4acd0b21d0bbb703ce4fe921e28eadc9f252348c1de4d6d114cf2',
                              'RSAPrivateKey', 'RSA', 512)
    dao.add_update_crypto_key(None, 'luacp', '9a2c5168bea132279bb4ce006e8a5c6ce210c073e1298848d0b4129c0549423d',
                              'RSAPrivateKey', 'encrypted', None)
    dao.add_update_crypto_key(None, 'server.pem', 'e8944eba6be07e26aeefe15893c47b9ab93828d2000e60033cd5db61e93a8910',
                              'RSAPrivateKey', 'RSA', 1024)
def addDefaultAccount():
    # 4 DefaultAccount DefaultAccountRelationship
    # class DefaultAccount(db.Model):
    #     __tablename__ = 'default_account'
    #     id = db.Column(db.Integer, primary_key=True)
    #     name = db.Column(db.String(512))
    #     pwd_hash = db.Column(db.String(512))
    #     hash_algorithm = db.Column(db.String(512))  # title: Hash algorithm, '0': DES, '1': '5': SHA2, '2a': Blowfish
    #     shell = db.Column(db.String(512))
    #     uid = db.Column(db.Integer)
    #     gid = db.Column(db.Integer)
    #     home_dir = db.Column(db.String(512))

    # class DefaultAccountRelationship(db.Model):
    #     __tablename__ = 'default_account_relationship'
    #     id = db.Column(db.Integer, primary_key=True)
    #     id_DefaultAccount = db.Column(db.Integer)  # Reference_key to DefaultAccount
    #     firmware_hash = db.Column(db.String(512))  # Reference_key to FirmwareInfo

    # add the data to the DefaultAccount table and DefaultAccountRelationship table

    # {
    #     "name": "sessioncgi",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 127,
    #     "gid": 127,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'sessioncgi', '*', None, '/bin/false', 127, 127, '/')
    dao.add_update_default_account_relationship(None, 1,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "environment",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 132,
    #     "gid": 132,
    #     "home_dir": "/"
    # },

    dao.add_update_default_account(None, 'environment', '*', None, '/bin/false', 132, 132, '/')
    dao.add_update_default_account_relationship(None, 2,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "mediaclipcgi",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 134,
    #     "gid": 254,
    #     "home_dir": "/"
    # },

    dao.add_update_default_account(None, 'mediaclipcgi', '*', None, '/bin/false', 134, 254, '/')
    dao.add_update_default_account_relationship(None, 3,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "wsdd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 136,
    #     "gid": 136,
    #     "home_dir": "/"
    # },

    dao.add_update_default_account(None, 'wsdd', '*', None, '/bin/false', 136, 136, '/')
    dao.add_update_default_account_relationship(None, 4,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "triggerd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 120,
    #     "gid": 120,
    #     "home_dir": "/"
    # },

    dao.add_update_default_account(None, 'triggerd', '*', None, '/bin/false', 120, 120, '/')
    dao.add_update_default_account_relationship(None, 5,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "tampering",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 122,
    #     "gid": 122,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'tampering', '*', None, '/bin/false', 122, 122, '/')
    dao.add_update_default_account_relationship(None, 6,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "storage",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 123,
    #     "gid": 123,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'storage', '*', None, '/bin/false', 123, 123, '/')
    dao.add_update_default_account_relationship(None, 7,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "focus",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 124,
    #     "gid": 124,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'focus', '*', None, '/bin/false', 124, 124, '/')
    dao.add_update_default_account_relationship(None, 8,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "wsd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 137,
    #     "gid": 137,
    #     "home_dir": "/"
    # },

    dao.add_update_default_account(None, 'wsd', '*', None, '/bin/false', 137, 137, '/')
    dao.add_update_default_account_relationship(None, 9,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "capbufd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 138,
    #     "gid": 138,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'capbufd', '*', None, '/bin/false', 138, 138, '/')
    dao.add_update_default_account_relationship(None, 10,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "bin",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/sh",
    #     "uid": 1,
    #     "gid": 1,
    #     "home_dir": "/bin"
    # },
    dao.add_update_default_account(None, 'bin', '*', None, '/bin/sh', 1, 1, '/bin')
    dao.add_update_default_account_relationship(None, 11,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "root",
    #     "pwd_hash": "AiADGkJIfIlXk",
    #     "hash_algorithm": "0",
    #     "shell": "/bin/sh",
    #     "uid": 0,
    #     "gid": 0,
    #     "home_dir": "/root"
    # },
    dao.add_update_default_account(None, 'root', 'AiADGkJIfIlXk', '0', '/bin/sh', 0, 0, '/root')
    dao.add_update_default_account_relationship(None, 12,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "anonymous",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 57,
    #     "gid": 57,
    #     "home_dir": "/var/empty/"
    # },
    dao.add_update_default_account(None, 'anonymous', '*', None, '/bin/false', 57, 57, '/var/empty/')
    dao.add_update_default_account_relationship(None, 13,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "daemon",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/sh",
    #     "uid": 2,
    #     "gid": 2,
    #     "home_dir": "/usr/sbin"
    # },
    dao.add_update_default_account(None, 'daemon', '*', None, '/bin/sh', 2, 2, '/usr/sbin')
    dao.add_update_default_account_relationship(None, 14,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "bw",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 102,
    #     "gid": 102,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'bw', '*', None, '/bin/false', 102, 102, '/')
    dao.add_update_default_account_relationship(None, 15,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "messagebus",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 101,
    #     "gid": 101,
    #     "home_dir": "/"
    # }
    dao.add_update_default_account(None, 'messagebus', '*', None, '/bin/false', 101, 101, '/')
    dao.add_update_default_account_relationship(None, 16,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "event",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 104,
    #     "gid": 104,
    #     "home_dir": "/"
    # }
    dao.add_update_default_account(None, 'event', '*', None, '/bin/false', 104, 104, '/')
    dao.add_update_default_account_relationship(None, 17,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "motion",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 103,
    #     "gid": 103,
    #     "home_dir": "/"
    # }
    dao.add_update_default_account(None, 'motion', '*', None, '/bin/false', 103, 103, '/')
    dao.add_update_default_account_relationship(None, 18,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "axisns",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 106,
    #     "gid": 106,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'axisns', '*', None, '/bin/false', 106, 106, '/')
    dao.add_update_default_account_relationship(None, 19,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "streamer",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 105,
    #     "gid": 105,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'streamer', '*', None, '/bin/false', 105, 105, '/')
    dao.add_update_default_account_relationship(None, 20,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "iod",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 109,
    #     "gid": 109,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'iod', '*', None, '/bin/false', 109, 109, '/')
    dao.add_update_default_account_relationship(None, 21,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "mld",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 108,
    #     "gid": 108,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'mld', '*', None, '/bin/false', 108, 108, '/')
    dao.add_update_default_account_relationship(None, 22,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "ptzadm",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 113,
    #     "gid": 113,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'ptzadm', '*', None, '/bin/false', 113, 113, '/')
    dao.add_update_default_account_relationship(None, 23,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "lang_handler",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 110,
    #     "gid": 110,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'lang_handler', '*', None, '/bin/false', 110, 110, '/')
    dao.add_update_default_account_relationship(None, 24,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "upnp",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 115,
    #     "gid": 115,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'upnp', '*', None, '/bin/false', 115, 115, '/')
    dao.add_update_default_account_relationship(None, 25,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "gtourd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 114,
    #     "gid": 114,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'gtourd', '*', None, '/bin/false', 114, 114, '/')
    dao.add_update_default_account_relationship(None, 26,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "stunnel",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 117,
    #     "gid": 117,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'stunnel', '*', None, '/bin/false', 117, 117, '/')
    dao.add_update_default_account_relationship(None, 27,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "rendezvous",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 116,
    #     "gid": 116,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'rendezvous', '*', None, '/bin/false', 116, 116, '/')
    dao.add_update_default_account_relationship(None, 28,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "acd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 119,
    #     "gid": 119,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'acd', '*', None, '/bin/false', 119, 119, '/')
    dao.add_update_default_account_relationship(None, 29,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "imaged",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 118,
    #     "gid": 118,
    #     "home_dir": "/"
    # },
    dao.add_update_default_account(None, 'imaged', '*', None, '/bin/false', 118, 118, '/')
    dao.add_update_default_account_relationship(None, 30,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "nobody",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 254,
    #     "gid": 254,
    #     "home_dir": "/var/empty"
    # },
    dao.add_update_default_account(None, 'nobody', '*', None, '/bin/false', 254, 254, '/var/empty')
    dao.add_update_default_account_relationship(None, 31,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "certcgi",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/false",
    #     "uid": 142,
    #     "gid": 142,
    #     "home_dir": "/"
    # }
    dao.add_update_default_account(None, 'certcgi', '*', None, '/bin/false', 142, 142, '/')
    dao.add_update_default_account_relationship(None, 32,
                                                'af88b1aaac0b222df8539f3ae1479b5c8eaeae41f1776b5dd2fa805cb33a1175')

    # {
    #     "name": "operator",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 11,
    #     "gid": 0,
    #     "home_dir": "/root"
    # },
    # {
    #     "name": "uucp",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 10,
    #     "gid": 14,
    #     "home_dir": "/var/spool/uucp"
    # },
    # {
    #     "name": "gopher",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 13,
    #     "gid": 30,
    #     "home_dir": "/var/gopher"
    # },
    dao.add_update_default_account(None, 'operator', '*', None, '/sbin/nologin', 11, 0, '/root')
    dao.add_update_default_account_relationship(None, 33,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'uucp', '*', None, '/sbin/nologin', 10, 14, '/var/spool/uucp')
    dao.add_update_default_account_relationship(None, 34,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'gopher', '*', None, '/sbin/nologin', 13, 30, '/var/gopher')
    dao.add_update_default_account_relationship(None, 35,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "games",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 12,
    #     "gid": 100,
    #     "home_dir": "/usr/games"
    # },
    # {
    #     "name": "nobody",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 99,
    #     "gid": 99,
    #     "home_dir": "/"
    # },
    # {
    #     "name": "ftp",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 14,
    #     "gid": 50,
    #     "home_dir": "/var/ftp"
    # },
    dao.add_update_default_account(None, 'games', '*', None, '/sbin/nologin', 12, 100, '/usr/games')
    dao.add_update_default_account_relationship(None, 36,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'nobody', '*', None, '/sbin/nologin', 99, 99, '/')
    dao.add_update_default_account_relationship(None, 37,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'ftp', '*', None, '/sbin/nologin', 14, 50, '/var/ftp')
    dao.add_update_default_account_relationship(None, 38,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "bin",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 1,
    #     "gid": 1,
    #     "home_dir": "/bin"
    # },
    # {
    #     "name": "root",
    #     "pwd_hash": "$1$We/2I...$Rc3UsEtZp5swSyIEHYkRS.",
    #     "hash_algorithm": "1",
    #     "shell": "/bin/bash",
    #     "uid": 0,
    #     "gid": 0,
    #     "home_dir": "/root"
    # },
    # {
    #     "name": "adm",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 3,
    #     "gid": 4,
    #     "home_dir": "/var/adm"
    # },
    dao.add_update_default_account(None, 'bin', '*', None, '/sbin/nologin', 1, 1, '/bin')
    dao.add_update_default_account_relationship(None, 39,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'root', '$1$We/2I...$Rc3UsEtZp5swSyIEHYkRS.', '1', '/bin/bash', 0, 0, '/root')
    dao.add_update_default_account_relationship(None, 40,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'adm', '*', None, '/sbin/nologin', 3, 4, '/var/adm')
    dao.add_update_default_account_relationship(None, 41,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "daemon",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 2,
    #     "gid": 2,
    #     "home_dir": "/sbin"
    # },
    # {
    #     "name": "sync",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/bin/sync",
    #     "uid": 5,
    #     "gid": 0,
    #     "home_dir": "/sbin"
    # },
    # {
    #     "name": "lp",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 4,
    #     "gid": 7,
    #     "home_dir": "/var/spool/lpd"
    # },
    dao.add_update_default_account(None, 'daemon', '*', None, '/sbin/nologin', 2, 2, '/sbin')
    dao.add_update_default_account_relationship(None, 42,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'sync', '*', None, '/bin/sync', 5, 0, '/sbin')
    dao.add_update_default_account_relationship(None, 43,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'lp', '*', None, '/sbin/nologin', 4, 7, '/var/spool/lpd')
    dao.add_update_default_account_relationship(None, 44,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "halt",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/halt",
    #     "uid": 7,
    #     "gid": 0,
    #     "home_dir": "/sbin"
    # },
    # {
    #     "name": "shutdown",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/shutdown",
    #     "uid": 6,
    #     "gid": 0,
    #     "home_dir": "/sbin"
    # },
    # {
    #     "name": "news",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "",
    #     "uid": 9,
    #     "gid": 13,
    #     "home_dir": "/etc/news"
    # },
    dao.add_update_default_account(None, 'halt', '*', None, '/sbin/halt', 7, 0, '/sbin')
    dao.add_update_default_account_relationship(None, 45,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'shutdown', '*', None, '/sbin/shutdown', 6, 0, '/sbin')
    dao.add_update_default_account_relationship(None, 46,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'news', '*', None, '', 9, 13, '/etc/news')
    dao.add_update_default_account_relationship(None, 47,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "mail",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "/sbin/nologin",
    #     "uid": 8,
    #     "gid": 12,
    #     "home_dir": "/var/spool/mail"
    # },
    # {
    #     "name": "man",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "",
    #     "uid": 16,
    #     "gid": 100,
    #     "home_dir": "/var/cache/man"
    # },
    # {
    #     "name": "telnetd",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "",
    #     "uid": 17,
    #     "gid": 100,
    #     "home_dir": "/var/tmp"
    # },
    dao.add_update_default_account(None, 'mail', '*', None, '/sbin/nologin', 8, 12, '/var/spool/mail')
    dao.add_update_default_account_relationship(None, 48,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'man', '*', None, '', 16, 100, '/var/cache/man')
    dao.add_update_default_account_relationship(None, 49,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'telnetd', '*', None, '', 17, 100, '/var/tmp')
    dao.add_update_default_account_relationship(None, 50,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')

    # {
    #     "name": "admin",
    #     "pwd_hash": "$1$Ktt0B/..$/ltIYihMm4YSL280ey/l./",
    #     "hash_algorithm": "1",
    #     "shell": "/bin/sh",
    #     "uid": 500,
    #     "gid": 500,
    #     "home_dir": "/"
    # },
    # {
    #     "name": "sys",
    #     "pwd_hash": "*",
    #     "hash_algorithm": null,
    #     "shell": "",
    #     "uid": 3,
    #     "gid": 3,
    #     "home_dir": "/dev"
    # }
    dao.add_update_default_account(None, 'admin', '$1$Ktt0B/..$/ltIYihMm4YSL280ey/l./', '1', '/bin/sh', 500, 500, '/')
    dao.add_update_default_account_relationship(None, 51,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')
    dao.add_update_default_account(None, 'sys', '*', None, '', 3, 3, '/dev')
    dao.add_update_default_account_relationship(None, 52,
                                                'aa96e4d41a4b0ceb3f1ae4d94f3cb445621b9501e3a9c69e6b9eb37c5888a03c')


def add_vulnerability():
    import csv
    csv_reader = csv.reader(open('./cvss.csv'))  # 读取cvss文件
    i = 0
    for line in csv_reader:
        dao.add_update_vulnerability(None, line[0] , line[3])
        i += 1
        if i > 10000:
            break
# 5 vulnerability relation riskSummary
def addRisk():
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '1', '1', '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '2', '2', 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '3', '3', '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '4', '4', '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '5', '5', '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '6', '6', '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '7', '7', '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '8', '8', '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '9', '9', '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
    dao.add_update_firmware_risk_summary_vulnerable_component_relation(None, '10', '10', '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

    add_vulnerability()

    dao.add_update_risk_summary(None, 'Critical', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Critical', 'Critica', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Hign', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Medium', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Critical', 'Critical', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Critical', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Critical', 'Critica', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Hign', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Medium', 'Hign', 'Medium', 'Low')
    dao.add_update_risk_summary(None, 'Critical', 'Critical', 'Medium', 'Low')

    dao.add_update_vulnerable_component(None, 'openssl', '0.9.7m', 'Crypto Library', '23,342,45,56,67,87,43,12,54,563,212', '5.9')
    dao.add_update_vulnerable_component(None, 'Endress+Hauser Fieldgate', 'FXA520', 'Fieldgate', '232,234,32,455,23,12,324,34,34,23,54,65,76,43,23,45,323,345,23,54,2343,45', '5.20')
    dao.add_update_vulnerable_component(None, 'CJ2M', '02.01', 'CPU', '2343,322,3434,323,1222,2332,43,2323,2343,2332,1234,4564,2333,2345,3423,345,6545', '5.20')
    dao.add_update_vulnerable_component(None, 'CJ2M', '1.11', 'CPU', '1112,1233,1412,1329,2313,2132,2343,5465,4533,4563,4532,4563,1233', '5.20')
    dao.add_update_vulnerable_component(None, 'NPort 5150', '3.4 Build 11080114', 'serial-to-IP converter', '435,124,657,223,123,32,87', '5.20')
    dao.add_update_vulnerable_component(None, 'Mitsubishi', 'Q-series', 'CPU', '234,435,654,345,234,456,245,78,213', '5.20')
    dao.add_update_vulnerable_component(None, 'power-misc', 'Null', 'Server', '332,123,435,657,345,44,32,43,76,34,65,76', '5.20')
    dao.add_update_vulnerable_component(None, 'pop3d', '4vO', 'Server', '77,234,322,232,123,34,23,54,56,342,234,564', '5.12')
    dao.add_update_vulnerable_component(None, 'imapd', 'Null', 'Server', '344,456,768,23,465,345,345,235,234', '5.20')
    dao.add_update_vulnerable_component(None, 'OpenSSH', '7.6p1 Ubuntu 4ubuntu0.3', 'Server', '23,454,656,22,34,546,23,34', '4.32')
    dao.add_update_vulnerable_component(None, 'libupnp', '1.4.1', 'UPnP Server', '2,6,7', '5.9')
    dao.add_update_vulnerable_component(None, 'CJ2M-EIP21', '2.7', 'EtherNet-IP-2', '1,2,3,4,6', '5.9')

    pass

def add_iot_data():
    addConfigIssue()
    addCryptoKey()
    addDefaultAccount()
    addExpiredCert()
    addRisk()

def test_for_data():
    # 测试1
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,1,2,'test1')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test2')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,1,3,'test3')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test4')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test5')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test6')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test7')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test8')
    # dao.add_update_firmware_risk_summary_vulnerable_component_relation(None,2,3,'test9')
    #
    # dao.add_update_risk_summary(None,'test0','eqw0','wqee0','qweqwe0')
    # dao.add_update_risk_summary(None,'test1','eqw1','wqee1','qweqwe1')
    # dao.add_update_risk_summary(None,'test2','eqw2','wqee2','qweqwe2')
    # dao.add_update_vulnerable_component(None,'test1','test2','test3','test4',1)
    # dao.add_update_vulnerable_component(None,'test2','test3','test4','test5',2)
    # dao.add_update_vulnerable_component(None,'test3','test4','test5','test6',3)

    # 测试2
    # dao.add_update_default_account_relationship(None,2,'test')
    # dao.add_update_default_account_relationship(None,3,'test1')
    # dao.add_update_default_account_relationship(None,2,'test2')
    # dao.add_update_default_account_relationship(None,3,'test3')
    # dao.add_update_default_account_relationship(None,3,'test4')
    #
    # dao.add_update_default_account(None,'test0','test1','test2','test3',1,2,'test4')
    # dao.add_update_default_account(None,'test1','test2','test3','test4',2,3,'test5')
    # dao.add_update_default_account(None,'test2','test3','test4','test5',3,2,'test6')
    # dao.add_update_default_account(None,'test3','test4','test5','test6',2,3,'test7')
    # dao.add_update_default_account(None,'test4','test5','test6','test7',3,2,'test8')
    # dao.add_update_default_account(None,'test5','test6','test7','test8',2,3,'test9')

    # 测试3
    # dao.add_update_crypto_key(None,'file_name1','filehash1','pem_type_1','sha1',10)
    # dao.add_update_crypto_key(None,'file_name2','filehash2','pem_type_2','sha2',20)
    # dao.add_update_crypto_key(None,'file_name3','filehash3','pem_type_3','sha3',30)
    # dao.add_update_crypto_key(None,'file_name4','filehash4','pem_type_4','sha4',40)
    # dao.add_update_crypto_key(None,'file_name5','filehash5','pem_type_5','sha5',50)
    # dao.add_update_crypto_key(None,'file_name6','filehash6','pem_type_6','sha6',60)
    # dao.add_update_crypto_key(None,'file_name7','filehash7','pem_type_7','sha7',70)
    # dao.add_update_crypto_key(None,'file_name8','filehash8','pem_type_8','sha8',80)
    #
    # dao.add_update_crypto_key_relation(None,1,'test1')
    # dao.add_update_crypto_key_relation(None,2,'test2')
    # dao.add_update_crypto_key_relation(None,3,'test3')
    # dao.add_update_crypto_key_relation(None,4,'test4')
    # dao.add_update_crypto_key_relation(None,5,'test5')
    # dao.add_update_crypto_key_relation(None,6,'test6')
    # dao.add_update_crypto_key_relation(None,7,'test7')
    # dao.add_update_crypto_key_relation(None,8,'test8')

    # 测试4
    # dao.add_update_expired_cert(None,'file1','test1','thumb1',1,'jjkk','from1','to1','sha1',10)
    # dao.add_update_expired_cert(None,'file2','test2','thumb2',2,'jjkk','from2','to2','sha2',20)
    # dao.add_update_expired_cert(None,'file3','test3','thumb3',3,'jjkk','from3','to3','sha3',30)
    # dao.add_update_expired_cert(None,'file4','test4','thumb4',4,'jjkk','from4','to4','sha4',40)
    # dao.add_update_expired_cert(None,'file5','test5','thumb5',5,'jjkk','from5','to5','sha5',50)
    # dao.add_update_expired_cert(None,'file6','test6','thumb6',6,'jjkk','from6','to6','sha6',60)
    # dao.add_update_expired_cert(None,'file7','test7','thumb7',7,'jjkk','from7','to7','sha7',70)
    # dao.add_update_expired_cert(None,'file8','test8','thumb8',8,'jjkk','from8','to8','sha8',80)
    #
    # dao.add_update_expired_cert_relation(None,1,'test1')
    # dao.add_update_expired_cert_relation(None,2,'test2')
    # dao.add_update_expired_cert_relation(None,3,'test3')
    # dao.add_update_expired_cert_relation(None,4,'test4')
    # dao.add_update_expired_cert_relation(None,5,'test5')
    # dao.add_update_expired_cert_relation(None,6,'test6')
    # dao.add_update_expired_cert_relation(None,7,'test7')
    # dao.add_update_expired_cert_relation(None,8,'test8')

    # 测试5
    # dao.add_update_weak_cert(None,'file1','test1','thumb1','sadas','jjkk','from1','to1')
    # dao.add_update_weak_cert(None,'file2','test2','thumb2','sadas','jjkk','from2','to2')
    # dao.add_update_weak_cert(None,'file3','test3','thumb3','sadas','jjkk','from3','to3')
    # dao.add_update_weak_cert(None,'file4','test4','thumb4','sadas','jjkk','from4','to4')
    # dao.add_update_weak_cert(None,'file5','test5','thumb5','sadas','jjkk','from5','to5')
    # dao.add_update_weak_cert(None,'file6','test6','thumb6','sadas','jjkk','from6','to6')
    # dao.add_update_weak_cert(None,'file7','test7','thumb7','sadas','jjkk','from7','to7')
    # dao.add_update_weak_cert(None,'file8','test8','thumb8','sadas','jjkk','from8','to8')
    #
    # dao.add_update_weak_cert_relation(None,1,'test1')
    # dao.add_update_weak_cert_relation(None,2,'test2')
    # dao.add_update_weak_cert_relation(None,3,'test3')
    # dao.add_update_weak_cert_relation(None,4,'test4')
    # dao.add_update_weak_cert_relation(None,5,'test5')
    # dao.add_update_weak_cert_relation(None,6,'test6')
    # dao.add_update_weak_cert_relation(None,7,'test7')
    # dao.add_update_weak_cert_relation(None,8,'test8')

    # 测试6
    # dao.add_update_config_issue(None,'HTTP','HTTP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'HTTPS','HTTPS.config','issues','suggestions')
    # dao.add_update_config_issue(None,'SMTP','SMTP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'POP3','POP3.config','issues','suggestions')
    # dao.add_update_config_issue(None,'IMAP','IMAP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'FTP','FTP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'DNS','DNS.config','issues','suggestions')
    # dao.add_update_config_issue(None,'LDAP','LDAP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'SSL','SSL.config','issues','suggestions')
    # dao.add_update_config_issue(None,'TLS','TLS.config','issues','suggestions')
    # dao.add_update_config_issue(None,'SSH','SSH.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Telnet','Telnet.config','issues','suggestions')
    # dao.add_update_config_issue(None,'RDP','RDP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'SMB','SMB.config','issues','suggestions')
    # dao.add_update_config_issue(None,'SNMP','SNMP.config','issues','suggestions')
    # dao.add_update_config_issue(None,'MSSQL','MSSQL.config','issues','suggestions')
    # dao.add_update_config_issue(None,'MYSQL','MYSQL.config','issues','suggestions')
    # dao.add_update_config_issue(None,'ORACLE','ORACLE.config','issues','suggestions')
    # dao.add_update_config_issue(None,'PostgreSQL','PostgreSQL.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Oracle','Oracle.config','issues','suggestions')
    # dao.add_update_config_issue(None,'MongoDB','MongoDB.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Redis','Redis.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Memcached','Memcached.config','issues','suggestions')
    # dao.add_update_config_issue(None,'RabbitMQ','RabbitMQ.config','issues','suggestions')
    # dao.add_update_config_issue(None,'ActiveMQ','ActiveMQ.config','issues','suggestions')
    # dao.add_update_config_issue(None,'OpenStack','OpenStack.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Apache','Apache.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Tomcat','Tomcat.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Nginx','Nginx.config','issues','suggestions')
    # dao.add_update_config_issue(None,'IIS','IIS.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Weblogic','Weblogic.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Websphere','Websphere.config','issues','suggestions')
    # dao.add_update_config_issue(None,'JBoss','JBoss.config','issues','suggestions')
    # dao.add_update_config_issue(None,'Tomcat','Tomcat.config','issues','suggestions')
    # dao.add_update_config_issue(None,'GlassFish','GlassFish.config','issues','suggestions')
    #
    #
    # dao.add_update_config_issue_relation(None,1,'test1')
    # dao.add_update_config_issue_relation(None,2,'test2')
    # dao.add_update_config_issue_relation(None,3,'test3')
    # dao.add_update_config_issue_relation(None,4,'test4')
    # dao.add_update_config_issue_relation(None,5,'test5')
    # dao.add_update_config_issue_relation(None,6,'test6')
    # dao.add_update_config_issue_relation(None,7,'test7')
    # dao.add_update_config_issue_relation(None,8,'test8')
    # dao.add_update_config_issue_relation(None,9,'test9')
    # dao.add_update_config_issue_relation(None,10,'test10')
    # dao.add_update_config_issue_relation(None,11,'test11')
    # dao.add_update_config_issue_relation(None,12,'test12')
    # dao.add_update_config_issue_relation(None,13,'test13')
    # dao.add_update_config_issue_relation(None,14,'test14')
    pass

def core_extract_banner(banner):
    if banner is None or len(banner) == 0:
        return ({'code':404,'msg':'banner is None'})
    dict1 = json.loads(banner)

    print(dict1)

    key = ""
    value = ""

    # 得到不空的key-value
    for i in dict1:
        if (dict1[i] != ""):
            key = i
            value = dict1[i]

    if (key == ""):
        print("key is None")
        return {'code': 404, 'error': 'Error'}

    device_info1 = None

    snmp_sysdescr = ""
    snmp_sysoid = ""
    ftp_banner = ""
    telnet_banner = ""
    hostname = ""
    http_response = ""
    https_response = ""
    upnp_response = ""
    nic_mac = ""

    try:
        if (key == "snmp_sysdescr"):
            device_info1 = dao.query_all_device_features(None, str(value), None, None, None, None, None, None, None,
                                                         None)
        elif (key == "snmp_sysoid"):
            device_info1 = dao.query_all_device_features(None, None, str(value), None, None, None, None, None, None,
                                                         None)
        elif (key == "ftp_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, str(value), None, None, None, None, None,
                                                         None)
        elif (key == "telnet_banner"):
            device_info1 = dao.query_all_device_features(None, None, None, None, str(value), None, None, None, None,
                                                         None)
        elif (key == "hostname"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, str(value), None, None, None,
                                                         None)
        elif (key == "http_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, str(value), None, None,
                                                         None)
        elif (key == "https_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, str(value), None,
                                                         None)
        elif (key == "upnp_response"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, str(value),
                                                         None)
        elif (key == "nic_mac"):
            device_info1 = dao.query_all_device_features(None, None, None, None, None, None, None, None, None,
                                                         str(value))
    except Exception as e:
        return {
            "code": 404,
            "data": "查询失败"
        }

    if (device_info1 is None):
        return {
            "code": 404,
            "data": "查询失败"
        }

    id = device_info1.id

    if (id is None):
        return {
            "code": 404,
            "data": "查询失败"
        }

    id_device_features = []
    for i in range(0, len(device_info1)):
        id_device_features.append(device_info1[i].id)

    data = []

    for i in range(0, len(id_device_features)):
        device_temp_info = dao.query_device_features_info_relation(None, id_device_features[i], None)
        id_device_info = device_temp_info.id_DeviceInfo
        id_device_features_info = device_temp_info.id_DeviceFeaturesInfo
        device_info = dao.query_device_infor(id_device_info, None, None, None, None, None, None, None, None, None, None,
                                             None, None, None, None, None)
        device_features = dao.query_device_features(id_device_features_info, None, None, None, None, None, None, None,
                                                    None, None)

        snmp_sysdescr = device_info.snmp_sysdescr
        snmp_sysoid = device_info.snmp_sysoid
        ftp_banner = device_info.ftp_banner
        telnet_banner = device_info.telnet_banner
        hostname = device_info.hostname
        http_response = device_info.http_response
        https_response = device_info.https_response
        upnp_response = device_info.upnp_response
        nic_mac = device_info.nic_mac
        manufacturer = device_features.manufacturer
        model_name = device_features.model_name
        firmware_version = device_features.firmware_version
        is_discontinued = device_features.is_discontinued
        cve_list = device_features.cve_list
        device_type = device_features.device_type
        firmware_info = device_features.firmware_info
        latest_firmware_info = device_features.latest_firmware_info

        dict = {
            "snmp_sysdescr": snmp_sysdescr,
            "snmp_sysoid": snmp_sysoid,
            "ftp_banner": ftp_banner,
            "telnet_banner": telnet_banner,
            "hostname": hostname,
            "http_response": http_response,
            "https_response": https_response,
            "upnp_response": upnp_response,
            "nic_mac": nic_mac,
            "manufacturer": manufacturer,
            "model_name": model_name,
            "firmware_version": firmware_version,
            "is_discontinued": is_discontinued,
            "cve_list": cve_list,
            "device_type": device_type,
            "firmware_info": firmware_info,
            "latest_firmware_info": latest_firmware_info
        }
        data.append(dict)
    return ({'code': 20000, 'data': data})