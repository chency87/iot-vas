import masscan
import nmap
import os
import json
from app.backend.controller.scan import *

class Task():
    def __init__(self, scan_name, scan_time, scan_ip, scan_port, script, ):
        """
        param scan_name 本次扫描命名
        type scan_name string

        param scan_time 本次扫描命名
        type scan_time 待定

        param scan_ip 目的ip
        type scan_ip string


        """
        self.scan_name = scan_name
        self.scan_time = scan_time
        self.scan_ip = scan_ip
        self.scan_port = scan_port
        self.script = script