
from app.conf.config import ScanScriptConf
import os
from time import  ctime,strptime
from datetime import datetime

def get_all_scripts():
    path = ScanScriptConf.SCRIPT_FOLDER
    scripts = os.listdir(path)
    script_list = []
    for script in scripts:
        abs_script_path = os.path.join(path,script)
        if (os.path.isfile(abs_script_path) and os.path.splitext(abs_script_path)[1] == '.nse'):
            # strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
            # print(strptime(str(ctime(os.path.getmtime(abs_script_path))),'%d %b %y'))
            last_modify_time = datetime.strptime(ctime(os.path.getmtime(abs_script_path)) , '%a %b %d %H:%M:%S %Y')
            # print(last_modify_time.strftime('%m/%d/%Y'))
            script_list.append({
                'name' : os.path.splitext(script)[0], 
                'last_modify_time': last_modify_time.strftime('%m/%d/%Y')
                })
    return script_list

def del_script_by_name(name):
    abs_path = get_abs_path(name)
    if (os.path.isfile(abs_path)):
        os.remove(abs_path)

def rename_script(oldname, newname):
    abs_path = get_abs_path(oldname)
    if (os.path.isfile(abs_path)):
        abs_new_path = get_abs_path(newname)
        if not abs_new_path.endswith('.nse'):
            abs_new_path = abs_new_path +'.nse'
        os.rename(abs_path, abs_new_path)

def get_abs_path(script):
    base_path = ScanScriptConf.SCRIPT_FOLDER
    script = script if script.endswith('.nse') else script  + '.nse'
    abs_path = os.path.join(base_path, script)
    return abs_path

def get_script_folder():
    return ScanScriptConf.SCRIPT_FOLDER