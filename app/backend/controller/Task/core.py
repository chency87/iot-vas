import masscan
import nmap
import os
import json
from app.backend.controller.scan import *

class Creat_task():
    def __init__(self, scan_name, scan_time ):
        self.scan_name = scan_name
        self.scan_time = scan_time
