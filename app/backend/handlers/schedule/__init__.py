from flask import Blueprint
schedule = Blueprint('schedule', __name__)


from . import core, view, template

