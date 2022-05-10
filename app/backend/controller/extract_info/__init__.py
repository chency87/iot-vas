from flask import Blueprint
extract_info = Blueprint('extract_info', __name__)


from . import core, view
