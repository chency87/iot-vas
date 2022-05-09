以后我们所有的逻辑都写在controller文件夹内，由于我们是通过蓝图形式，所以大家可以自由的创建文件夹，文件夹结构参考 scan

一个蓝图就相当于我们以后的一个功能模块。类似于我们应用的左侧菜单栏的一个按钮。


创建文件后，需要修改__init__.py 文件，加入如下代码，注意修改scan为你自己对应的文件夹名称, 文件夹不得出现重复

from flask import Blueprint
scan = Blueprint('scan', __name__)  将scan修改为你自己对应的文件夹名称
from . import core, view

当我们创建一个文件夹后，需要在项目根目录中的__init__.py文件内，注册该蓝图。步骤如下：
1. 引入你创建的这个包，例如：
from app.backend.controller.scan import scan as scan_blueprint

2. 找到register_blueprints函数，并将你这个blueprint加进去，代码格式如下：

def register_blueprints(app):
    app.register_blueprint(schedule_blueprint)
    app.register_blueprint(finger_blueprint)
    app.register_blueprint(setting_blueprint)
    app.register_blueprint(logger_blueprint)
    app.register_blueprint(plugins_blueprint)


## 每个文件的功能作用
__init__.py 声明这是一个blueprint
core.py 这个模块所对应的核心逻辑代码，根据具体需要，可以创建其他的py文件
view.py 对http请求进行响应，具体可以参考下面的例子： 其中@finger.route这一行用于表示我们对 /finger/details的链接的get方法进行响应。根据具体的模块不同，需要将finger修改为你的blueprint的名字，如scan.route('XXXXX')，函数内的逻辑根据自己的业务情况来写，进而返回jsonify内容即可。

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

## 如何运行你定义的函数代码，
假设在scan文件夹内的view.py中，写了如下函数（可以参考handlers文件夹内的finger/view.py或者其他的module）：那么当你运行整个项目后，通过浏览器地址栏输入http://127.0.0.1:5000/scan/show 即可调用show_scan这个函数，其他函数方法同理。

**推荐下载安装postman，这样可以对POST/PUT/DELETE方法进行调用**

@scan.route('/scan/show', methods=['GET'])
def show_scan():
    response = {'status' : -1}
    response['recordsTotal'] = 1#fingers.total
    response['recordsFiltered'] =1 # fingers.total
    response['data'] = dic
    return jsonify(response)
