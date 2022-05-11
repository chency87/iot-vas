from app.backend.controller.scan.core import Scan
from app.backend.controller.Task.core import Task
import nmap
import masscan
def test():
    info = {"name": "test", "desc": "desc", "target": "198.53.49.46", "port": "1-1000", "rate": 10000,
            "scan_type": ["TCP_Scan", "UDP_Scan"],
            "config": ["open_port", "service"], "vuldb": ["xforce", "vuldb", "openvas", "cve"],
            "script": ["snmp-interfaces", "snmp-sysdescr"]}

    task = Task(info=info)
    result = task.create_task()
    print(result)
    return result

test()

