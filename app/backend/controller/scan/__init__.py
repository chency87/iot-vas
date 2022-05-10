from flask import Blueprint
scan= Blueprint('scan', __name__)
from . import core, view

