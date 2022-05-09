from flask import Blueprint
plugins = Blueprint('scan', __name__)


from . import core, view

