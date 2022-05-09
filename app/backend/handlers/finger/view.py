import re
from werkzeug.wrappers import response
from . import finger
from flask import json, render_template,request, jsonify, redirect,url_for
from urllib.parse import unquote
from flask_login import login_user, current_user, login_required

from flask_sqlalchemy import Pagination
from libnmap.parser import NmapParser
from .core import get_all_device_by_paginate, del_device_by_id
@finger.route('/finger/details', methods=['GET'])
def show_finger():
    response = {'status' : -1}
    start = int(request.args.get('start'))
    length = int(request.args.get('length'))
    page = int(start / length  + 1)
    # print(length)
    # print(page)
    if start is not None and length is not None:
        fingers = get_all_device_by_paginate(page = page,per_page= length)
        dic = []
        for item in fingers.items:
            print(item.to_json())
            dic.append(item.to_json())
            
        response['recordsTotal'] = 1#fingers.total
        response['recordsFiltered'] =1 # fingers.total
        response['data'] = dic
    return jsonify(response)
@finger.route('/finger/details/delete', methods=['GET'])    
@login_required
def del_finger():
    id = request.args.get('id')
    del_device_by_id(int(id))
    response= {'status': 200}
    # return render_template('pages/finger/finger.html', title="Fingers", header="指纹管理", nav="Finger Manage", form = current_user)
    return redirect('/finger/index')

@finger.route('/finger/device/detect', methods=['POST'])    
@login_required
def detect_device():
    search_data = request.get_json(force=True)
    # print(search_data)
    


    response= {'status': 200, 'data' : search_data}
    
    # return render_template('pages/finger/finger.html', title="Fingers", header="指纹管理", nav="Finger Manage", form = current_user)
    return jsonify(response)


@finger.route('/finger/index',  methods=['GET'])
def finger_page():
    return render_template('pages/devices/index.html', title="Fingers", header="指纹管理", nav = ' ss',form = current_user)


