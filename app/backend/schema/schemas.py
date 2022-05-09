#!/usr/bin/python
# -*- coding: utf-8 -*-

from marshmallow import Schema, fields


class BaseUserSchema(Schema):
    """
    Base user schema returns all fields but this was not used in user handlers.
    """
    # Schema parameters.
    id = fields.Int(dump_only=True)
    username = fields.Str()
    email = fields.Str()
    password = fields.Str()
    created = fields.Str()
    modified = fields.Str()
    user_role = fields.Str()
    lastlogin = fields.Str()


class UserSchema(Schema):

    """
    User schema returns only username, email and creation time. This was used in user handlers.
    """

    # Schema parameters.

    username = fields.Str()
    email = fields.Str()
    created = fields.Str()
    user_role = fields.Str()

    # class Meta:
    #     fields =['username','email','created']
    #     ordered = True


class DeviceInfoSchema(Schema):
    manufacturer = fields.Str()
    # {
    #     "manufacturer": "string",
    #     "model_name": "string",
    #     "firmware_version": "string",
    #     "is_discontinued": true,
    #     "cve_list": [
    #         {
    #         "cve_id": "string",
    #         "cvss": 0
    #         }
    #     ],
    #     "device_type": "string",
    #     "firmware_info": {
    #         "name": "string",
    #         "version": "string",
    #         "sha2": "string",
    #         "release_date": "string",
    #         "download_url": "string"
    #     },
    #     "latest_firmware_info": {
    #         "name": "string",
    #         "version": "string",
    #         "sha2": "string",
    #         "release_date": "string",
    #         "download_url": "string"
    #     }
    #     }

