from app.backend.controller.scan.core import Scan
import uuid
from app.backend.extensions import scheduler
import datetime


def exe_task():
    info = {"name": "test", "desc": "desc", "target": "198.53.49.46", "port": '1-1000', "rate": 10000,
            "scan_type": ["TCP_Scan", "UDP_Scan"],
            "config": ["open_port", "service"], "vuldb": ["xforce", "vuldb", "openvas", "cve"],
            "script": ["snmp-interfaces", "snmp-sysdescr"],
            "schedule": {"triggers": "date"}
            }

    task = Task(info=info)
    task.create_task()


class Task(object):
    def __init__(self, info):
        """
        param scan_name 本次扫描命名
        type scan_name string

        param scan_time 本次扫描命名
        type scan_time string ""

        param scan_ip 目的ip
        type scan_ip string
        """
        self.scan_name = None
        self.scan_desc = None
        self.scan_ip = None
        self.scan_type = None
        self.scan_port = None
        self.config = None
        self.script_argument = "--script="
        self.script = None
        self.rate = None
        self.info = info
        self.scan_argument = ""

    def info_process(self):
        self.scan_name = self.info['name']
        self.scan_ip = self.info['target']
        self.scan_port = self.info['port']
        self.rate = "--max-rate=" + str(self.info['rate'])
        self.config = self.info['config']
        self.scan_desc = self.info['desc']
        self.script = self.info['script']
        self.rate = self.info['rate']
        self.scan_type = self.info['scan_type']

    def set_config(self):
        """
        配置 扫描 os  端口服务等信息
        """
        configs = self.config
        for config in configs:
            if config == 'os':
                self.scan_argument = self.scan_argument + ' ' + '-O'
            elif config == 'service':
                self.scan_argument = self.scan_argument + ' ' + '-sV'
            elif config == 'vul':
                self.script_argument = self.script_argument + 'vulscan/vulscan.nse,'
            elif config == 'banner':
                self.script_argument = self.script_argument + 'banner.nse,'

    def set_script(self):
        scripts = self.script
        for script in scripts:
            self.script_argument = self.script_argument + script + ','

    def set_scan_type(self):
        scan_types = self.scan_type
        for scan_type in scan_types:
            if scan_type == 'SYN_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sS'
            elif scan_type == 'TCP_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sT'
            elif scan_type == 'UDP_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sU'
            elif scan_type == 'Ping_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sP'

    # 暂时还不知道怎么配置vuldb
    def set_vuldb(self):
        return

    def create_task(self):
        # 信息处理部分
        self.info_process()
        self.set_config()
        self.set_scan_type()
        self.set_vuldb()
        self.set_script()

        sc = Scan(ip=self.scan_ip, ports=self.scan_port, scan_argument=self.scan_argument,
                  script_argument=self.script_argument, sacn_rate=self.rate)
        result = sc.basic_detection()
        sc.process_result(result=result)

        configs = self.config
        # 配置信息获取部分
        for config in configs:
            if config == 'service':
                sc.service(result=result)
            elif config == 'vul':
                sc.vul_detection(result=result)

        # 脚本信息获取部分
        for script in self.script:
            if script == 'snmp-interfaces' or "snmp-sysdecsr":
                sc.snmp_info(result=result)
            elif script == 'vulscan/vulscan':
                sc.vul_detection(result=result)
        print()
        return sc.get_result()


class Schedule(object):
    def __init__(self, info):
        self.info = info
        self.triggers = None
        self.time = None
        self.year = None
        self.month = None
        self.week = None
        self.day = None
        self.hour = None
        self.minute = None
        self.scheduler = scheduler

    def init_task(self):
        self.triggers = self.info['schedule']['triggers']
        # 通过伪随机码创造ID
        task_id = "{}-{}".format(self.triggers, uuid.uuid4().hex)
        return task_id

    def add_task(self):
        # 创建任务类
        task = Task(self.info)
        # 立即执行任务
        func = __name__ + ":" + "exe_task"
        id = self.init_task()
        if self.triggers == 'date':
            self.scheduler.add_job(func=func, trigger=self.triggers, run_date=datetime.datetime.now(), id=id)
            print(scheduler.get_jobs())
            self.scheduler.start()
            print(scheduler.get_jobs())

        # 定时任务以后再说
        elif self.triggers == 'interval':
            self.scheduler.add_job(func=task.create_task(), trigger=self.triggers, seconds=5, id=id)
        elif self.triggers == 'cron':
            self.scheduler.add_job(func=task.create_task(), trigger=self.triggers, year=self.year, month=self.month,
                                   week=self.week, day=self.day, hour=self.hour, minute=self.minute)

    def remove_task(self, id):
        self.scheduler.remove_job(job_id=id)



info = {"name": "test", "desc": "desc", "target": "198.53.49.46", "port": '1-1000', "rate": 10000,
        "scan_type": ["TCP_Scan", "UDP_Scan"],
        "config": ["open_port", "service"], "vuldb": ["xforce", "vuldb", "openvas", "cve"],
        "script": ["snmp-interfaces", "snmp-sysdescr"],
        "schedule": {"triggers": "date"}
        }

sch = Schedule(info=info)
sch.add_task()
