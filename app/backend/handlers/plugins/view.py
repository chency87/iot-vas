import re
from . import plugins
from flask import json, render_template,request, jsonify, flash, send_file, redirect
from werkzeug.utils import secure_filename
from urllib.parse import unquote
from flask_login import login_user, current_user, login_required
from .core import get_all_scripts,del_script_by_name, rename_script, get_script_folder, get_abs_path
# import os

ALLOWED_EXTENSIONS = {'nse'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@plugins.route('/plugins', methods = ['GET', 'POST'])
@login_required
def show_plugins_page():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # filename = secure_filename(file.filename)
            file.save(get_abs_path(secure_filename(file.filename)))
            flash('文件上传成功')
        else:
            flash('请正确选择文件')

    scripts = get_all_scripts()
    return render_template('pages/plugins/index.html', title="Plugins", header="感知终端识别解析插件管理", nav="Plugin Manage", form = current_user, scripts = scripts)


@plugins.route('/plugins/delete', methods = ['DELETE'])
@login_required
def delete_plugin_by_name():
    script_name = request.args.get('script')
    del_script_by_name(script_name)
    scripts = get_all_scripts()
    return jsonify(scripts)

@plugins.route('/plugins/rename', methods = ['POST'])
@login_required
def rename_plugin():
    oldname = request.form.get('oldname')
    newname = request.form.get('newname')
    rename_script(oldname, newname)
    return jsonify({})

@plugins.route('/plugins/export', methods=['GET'])
@login_required
def download():
    script_name = request.args.get('script')
    abs_path = get_abs_path(script_name)
    script_name = script_name if script_name.endswith('.nse') else script_name + '.nse'
    directory = get_script_folder()
    return send_file(abs_path,attachment_filename=script_name, as_attachment=True)


    # return send_from_directory(directory=directory, filename=script_name)
