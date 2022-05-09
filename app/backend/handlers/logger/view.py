from . import logger
from flask import json, render_template,request, jsonify
from flask_login import current_user, login_required

from app.backend.schema.schemas import UserSchema
# from .core import get_log_info_by_name
from .core import log_handler, LogActions, ActionResult




@logger.route('/settings/logmanage.html', methods=['GET'])
def show_log_page():
    user = UserSchema().dump(current_user)
    
    # log_handler.add_log(request , 'Watch', 'INFO', 'search log' )
    # logs = log_handler.query_log(0,10)
    
    # for item in logs.items:
    #     print(item.to_json())
    return render_template('pages/settings/logmanage.html', title="操作日志查看", header="系统操作日志管理", form = user)




@logger.route('/settings/logdetails', methods=['GET'])
def show_log_details():
    response = {}
    start = int(request.args.get('start'))
    per_page = int(request.args.get('length'))
    # print(start)
    # print(per_page)
    # log_handler.add_log(request, LogActions.LOG_IN , ActionResult.success, 'login')
    # print('---' *50)

    page = start / per_page  + 1
    if start is not None and per_page is not None:
        logs = log_handler.query_log(page, per_page)
        dic = []
        for item in logs.items:
            dic.append(item.to_json())
            
        response['recordsTotal'] = logs.total
        response['recordsFiltered'] = logs.total
        response['data'] = dic
        
    return response


