from app.backend.controller.scan.core import Scan
import uuid
from app.backend.extensions import scheduler
import datetime
from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db
import re
from app.backend.models.Task_data.curd import add_schedule_history

# from app.backend.models.Task_data.curd import


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

    info = dict(
        name="",
        target="",
        task_id="",
        port="",
        rate="",
        scan_type=[],
        config=["", "", "", ""],
        scan_desc="",
        script="",

    )

    def info_process(self):
        self.scan_name = self.info['name'] or None
        self.scan_ip = self.info['target'] or None
        self.scan_port = self.info['port'] or None
        self.rate = "--max-rate=" + str(self.info['rate']) or None
        self.config = self.info['config'] or None
        self.scan_desc = self.info['desc'] or None
        self.script = self.info['script'] or None
        self.scan_type = self.info['scan_type'] or None

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
            if scan_type == 'TCP_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sT'
            if scan_type == 'UDP_Scan':
                self.scan_argument = self.scan_argument + ' ' + '-sU'
            if scan_type == 'Ping_Scan':
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
        sc.init_result(result=result)

        configs = self.config
        # 配置信息获取部分
        for config in configs:
            if config == 'service':
                sc.service(result=result)
            elif config == 'vul':
                sc.vul_detection(result=result)

        # 脚本信息获取部分
            if re.search('snmp-sysdesc',self.script):
                sc.snmp_info(result=result)
            if re.search('vulscan/vulscan',self.script):
                sc.vul_detection(result=result)
            if re.search('banner',self.script):
                sc.get_banner(result=result)

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

    def init_task_id(self):
        self.triggers = self.info['schedule']['triggers']
        # 通过伪随机码创造ID
        task_id = "{}-{}".format(self.triggers, uuid.uuid4().hex)
        return task_id

    def add_task(self):
        # 创建任务类
        task = Task(self.info)
        # 立即执行任务
        func = __name__ + ":" + "exe_task"
        if self.info["task_id"] == "":
           task_id = self.init_task_id()  # 从self.info 里面看有没有task_id   逻辑改一下
        if self.triggers == 'date':
            self.scheduler.add_job(func=func, trigger=self.triggers, run_date=datetime.datetime.now(), id=task_id,
                                   kwargs={"params": self.info, "id": task_id})  # kwargs表示向函数里func里传参

            print(scheduler.get_jobs())

        # 定时任务以后再说
        elif self.triggers == 'interval':
            self.scheduler.add_job(func=task.create_task(), trigger=self.triggers, seconds=5, id=id)
        elif self.triggers == 'cron':
            self.scheduler.add_job(func=task.create_task(), trigger=self.triggers, year=self.year, month=self.month,
                                   week=self.week, day=self.day, hour=self.hour, minute=self.minute)

    def remove_task(self, id):
        self.scheduler.remove_job(job_id=id)


def exe_task(params, id):
    print(params)
    create_time = datetime.datetime.now()
    task = Task(info=params)
    scan_report = task.create_task()
    end_time = datetime.datetime.now()
    add_schedule_history(id=id, create_time=create_time, scan_report=scan_report, end_time=end_time,params=params)

# 增删改查    定时任务的暂停，启动  已经完成的再运行一遍
# task_id 创建时间 完成时间 info参数 scan_report