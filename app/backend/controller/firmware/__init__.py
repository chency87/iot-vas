from flask import Blueprint
firmware = Blueprint('firmware', __name__)


from . import core, view
