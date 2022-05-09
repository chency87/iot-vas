from datetime import datetime
from flask import render_template, request, redirect, url_for, make_response
from flask_login import login_user, current_user, login_required

from flask_login.utils import logout_user
from flask import jsonify
from marshmallow.fields import Method
from werkzeug.wrappers import response


from app import app
# from app.backend.forms import login_form
from app.backend.forms import login_form
from app.backend.models.user import User
from app.backend.handlers import user_handler
from app.backend.permission import role_required
from app.backend.permission.role_required import Role
from app.backend.schema.schemas import UserSchema, BaseUserSchema

from app.backend.handlers.logger.core import log_handler, LogActions, ActionResult

@app.login_manager.user_loader
def load_user(id):
    data = User.query.get(id)
    return data

@app.login_manager.unauthorized_handler
def unauthorized_callback():
    # redirect('/login.html?next=' + request.path)
    response = {'status': '401', 'next' : request.path}
    return redirect('/login.html?next=' + request.path)

@app.route('/login.html' ,  methods=('GET', 'POST'))
def login():
    form = login_form.LoginForm()
    emsg = None
    if form.validate_on_submit():
        user_name = request.form.get('username', None)
        password = request.form.get('password', None) 
        remember_me = request.form.get('remember_me', False)       
        msg = user_handler.login(user_name, password)
        if msg[1] == 200:
            info = msg[0]
            login_user(info.get('user_info'), remember= remember_me)
            resp = make_response(redirect(request.args.get('next') or url_for('index')))
            resp.set_cookie('access_token', info.get('access_token'))
            resp.set_cookie('refresh_token', info.get('refresh_token'))
            log_handler.add_log(request, LogActions.LOG_IN, ActionResult.success, '{} login success'.format(user_name))
            return resp
        else:
            emsg = msg[0]
    return render_template('pages/login.html', title="Login", form = form, emsg = emsg)

@app.route('/logout')
@login_required
def logout():
    log_handler.add_log(request, LogActions.LOG_OUT, ActionResult.success, ' logout success')
    logout_user()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp

@app.route('/')
@app.route('/index.html')
@login_required
@role_required.permission(Role.admin)
def index():
    # print(current_user)
    data = UserSchema().dump(current_user)
    return render_template('pages/index.html', title="Home", header="Home", form = data)

@app.route('/settings/usermanage', methods= (['GET']))
@login_required
def setting_user():
    return render_template('pages/settings/usermanage.html', title="User Management", header="用户管理", nav="User Management", form = current_user)


@app.route('/settings/usermanage/all' ,  methods=(['GET']))
@login_required
def setting_user_all_user():
    user_list = user_handler.query_all_user()
    # print(user_list)
    return jsonify(user_list)

@app.route('/settings/usermanage', methods = (['DELETE']))
@login_required
def setting_users_delete():
    ids = request.args.get('ids').split(',')
    user_handler.delete_users(ids)
    return jsonify('success')

@app.route('/settings/usermanage', methods = (['POST']))
@login_required
def setting_users_add():
    id = request.form.get('id')
    username = request.form.get('username')
    email = request.form.get('email')
    user_role = request.form.get('user_role')
    password = request.form.get('password')
    msg = user_handler.add_update_user(id,username,password,email, user_role)

    log_handler.add_log(request, LogActions.ADD_USER, ActionResult.success, str(msg))
    return jsonify(msg)

@app.route('/userprofile' ,  methods=(['GET','POST']))
@login_required
def setting_user_profile():
    user = current_user
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        user = user_handler.update_user(user.id,username,email)
        log_handler.add_log(request, LogActions.EDIT_USER, ActionResult.success, str(user))
    return render_template('pages/settings/userprofile.html', title="User Profile", header="用户信息管理", nav="User Profile", form = BaseUserSchema().dump(user))



@app.route('/resetpassword' ,  methods=(['POST']))
@login_required
def reset_password():
    user = current_user
    old_pass = request.form['old_pass']
    new_pass = request.form['new_pass']
    status = user_handler.reset_password(user.username, old_pass, new_pass)
    log_handler.add_log(request, LogActions.EDIT_USER, ActionResult.success, str(status))
    # print(status)
    return render_template('pages/settings/userprofile.html', title="User Profile", header="用户信息管理", nav="User Profile", form = BaseUserSchema().dump(user))



@app.route('/settings/system')
def setting_system():
    return render_template('pages/settings/systemsetting.html', title="System Management", header="系统设置", nav="System Management", form = current_user)

@app.route('/flot.html')
def flot():
    return render_template('pages/flot.html', title="Flot", header="Flot Charts", nav="Flot Page", form = current_user)

@app.route('/morris.html')
def morris():
    return render_template('pages/morris.html', title="Morris", header="Morris.js Charts", nav="Morris Page", form = current_user)

@app.route('/tables.html')
def tables():
    return render_template('pages/tables.html', title="Tables", header="Tables", nav="Tables Page", form = current_user)

@app.route('/forms.html')
def forms():
    return render_template('pages/forms.html', title="Forms", header="Forms", nav="Forms Page", form = current_user)

@app.route('/panels-wells.html')
def panels_wells():
    return render_template('pages/panels-wells.html', title="Panels and Wells", header="Panels and Wells", nav="Panels and Wells Page", form = current_user)

@app.route('/buttons.html')
def buttons():
    return render_template('pages/buttons.html', title="Buttons", header="Buttons", nav="Buttons Page", form = current_user)

@app.route('/notifications.html')
def notifications():
    return render_template('pages/notifications.html', title="Notifications", header="Notifications", nav="Notifications Page", form = current_user)

@app.route('/typography.html')
def typography():
    return render_template('pages/typography.html', title="Typography", header="Typography", nav="Typography Page", form = current_user)

@app.route('/icons.html')
def icons():
    return render_template('pages/icons.html', title="Icons", header="Icons", nav="Icons Page", form = current_user)

@app.route('/grid.html')
def grid():
    return render_template('pages/grid.html', title="Grid", header="Grid", nav="Grid Page", form = current_user)