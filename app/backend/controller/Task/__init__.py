from flask import Blueprint
Task = Blueprint('Task', __name__)
from . import core, view