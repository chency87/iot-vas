import schedule
import time
from app.backend.controller.scan.core import Scan


class Task():
    def __init__(self, scan_name, scan_time, scan_ip, scan_port, scan_argument, script, ):
        """
        param scan_name 本次扫描命名
        type scan_name string

        param scan_time 本次扫描命名
        type scan_time string ""

        param scan_ip 目的ip
        type scan_ip string

        """
        self.scan_name = scan_name
        self.scan_time = scan_time
        self.scan_ip = scan_ip
        self.scan_port = scan_port
        self.scan_argument = scan_argument
        self.script = script

    def exe_task(self):
        scan = Scan(ip=self.scan_ip, ports=self.scan_port, scan_argument=self.scan_argument, script_name=self.script)
        schedule.every().hour.do(scan.scan())
