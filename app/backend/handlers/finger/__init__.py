from flask import Blueprint
finger = Blueprint('finger', __name__)


from . import core, view

