from flask import Flask, send_from_directory
import os

from flask_login import LoginManager
from app import conf
from app.backend.error.apiexception import APIException, ServerError
from werkzeug.exceptions import HTTPException

from app.conf import config
from app.backend.database.database import db
from app.backend.database.db_initializer import (create_admin_user,
                                                 create_super_admin,
                                                 create_test_user)

from app.backend.handlers.schedule import schedule as schedule_blueprint
from app.backend.handlers.finger import finger as finger_blueprint
from app.backend.handlers.settings import setting as setting_blueprint
from app.backend.handlers.logger import logger as logger_blueprint
from app.backend.handlers.plugins import plugins as plugins_blueprint
from app.backend.extensions import scheduler
from app.backend.controller.extract_info import extract_info as extract_info_blueprint
from app.backend.controller.Task import Task as Task_blueprint
from app.backend.controller.scan import scan as scan_blueprint
from app.backend.controller.extract_info import extract_info as extract_info_blueprint
from app.backend.controller.firmware import firmware as firmware_blueprint


def init_app(config_name=None):
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'default')
    app = Flask(__name__, static_url_path='')
    app.config['SQLALCHEMY_DATABASE_URI'] = config.db['SQLALCHEMY_DATABASE_URI']
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.db['SQLALCHEMY_TRACK_MODIFICATIONS']
    app.config['SCHEDULER_API_ENABLED'] = True
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
    app.config['JSON_AS_ASCII'] = False

    # app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

    app.config.from_object(config.TaskConfig)
    register_extensions(app)
    register_blueprints(app)
    init_script_folder()

    db.app = app
    # Create all database tables.
    db.create_all()
    # Create default super admin user in database.
    create_super_admin()
    create_admin_user()
    create_test_user()
    return app


def init_script_folder():
    if not os.path.exists(config.UPLOAD_FOLDER):
        os.makedirs(config.UPLOAD_FOLDER)


# 注册蓝图
def register_blueprints(app):
    app.register_blueprint(schedule_blueprint)
    app.register_blueprint(finger_blueprint)
    app.register_blueprint(setting_blueprint)
    app.register_blueprint(logger_blueprint)
    app.register_blueprint(plugins_blueprint)
    app.register_blueprint(extract_info_blueprint)
    app.register_blueprint(Task_blueprint)
    app.register_blueprint(scan_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth')
    # app.register_blueprint(job_blueprint,url_prefix='/v1/cron/job')


def register_extensions(app):
    # use login manager to manage session
    login_manager = LoginManager()
    login_manager.session_protection = 'strong'
    login_manager.login_view = 'login'
    login_manager.init_app(app=app)
    db.init_app(app)
    # initialize scheduler
    # scheduler = APScheduler()
    # if you don't wanna use a config, you can set options here:
    # scheduler.api_enabled = True
    scheduler.init_app(app)



app = init_app()


@app.errorhandler(Exception)
def server_error_handler(e):
    if isinstance(e, APIException):
        return e
    if isinstance(e, HTTPException):
        code = e.code
        msg = e.description
        error_code = 1007
        return APIException(msg, code, error_code)
    else:
        if not app.config['DEBUG']:
            return ServerError()
        else:
            return e


@app.route('/bower_components/<path:path>')
def send_bower(path):
    return send_from_directory(os.path.join(app.root_path, 'statics/bower_components'), path)


@app.route('/dist/<path:path>')
def send_dist(path):
    return send_from_directory(os.path.join(app.root_path, 'statics/dist'), path)


@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory(os.path.join(app.root_path, 'statics/js'), path)


from app import views
