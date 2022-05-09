from flask import Blueprint
setting = Blueprint('settings', __name__)


from . import core, view

