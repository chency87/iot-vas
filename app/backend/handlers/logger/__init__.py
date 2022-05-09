from flask import Blueprint
logger = Blueprint('logger', __name__)


from . import core, view

