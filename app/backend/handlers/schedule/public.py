import subprocess
import platform
import json
import datetime
from datetime import date

def exec_shell(cmd):
    '''执行shell命令函数'''
    if "rm" in cmd:
        return False
    sub2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = sub2.communicate()
    ret = sub2.returncode
    print(stderr)

    if(platform.system()=='Windows'):
        return ret, stdout.decode('gbk')
    else:
        return ret, stdout.decode('utf-8')

class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        else:
            return json.JSONEncoder.default(self, obj)