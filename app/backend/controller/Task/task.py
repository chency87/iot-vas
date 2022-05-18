from app.backend.controller.scan.core import Scan
import uuid
from app.backend.extensions import scheduler
import datetime
from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db
import re
from app.backend.models.Task_data.curd import add_schedule_history
from app.backend.models.dao.dao import use_report


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
        script=["snmp*"],

    )

    def info_process(self):
        self.scan_name = self.info['name'] if 'name' in self.info else ""
        self.scan_ip = self.info['target'] if 'target' in self.info else ""
        self.scan_port = self.info['port'] if 'port' in self.info else ""
        self.rate = ("--max-rate=" + str(self.info['rate'])) if 'rate' in self.info else ""
        self.config = self.info['config'] if 'config' in self.info else ""
        self.scan_desc = self.info['desc'] if 'desc' in self.info else ""
        self.script = self.info['script'] if 'script' in self.info else ""
        self.scan_type = self.info['scan_type'] if 'scan_type' in self.info else ""

    def set_config(self):
        """
        配置 扫描 os  端口服务等信息
        """
        configs = self.config
        for config in configs:
            if config == 'os':
                self.scan_argument = self.scan_argument + ' ' + '-O'
            if config == 'service':
                self.scan_argument = self.scan_argument + ' ' + '-sV'
            if config == 'vul':
                self.script_argument = self.script_argument + 'vulscan/vulscan.nse,'
            if config == 'banner':
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

        print(self.scan_ip)
        print(self.scan_port)
        print(self.scan_argument)
        print(self.script_argument)
        print(self.rate)

        sc = Scan(ip=self.scan_ip, ports=self.scan_port, scan_argument=self.scan_argument,
                  script_argument=self.script_argument, sacn_rate=self.rate)
        # 先进行基础检测
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
            if 'snmp*' in self.script:
                sc.snmp_info(result=result)
            if 'vulscan/vulscan' in self.script:
                sc.vul_detection(result=result)
            if 'banner' in self.script:
                sc.get_banner(result=result)
        print(sc.get_result())
        return sc.get_result()


class Schedule(object):
    def __init__(self, info):
        self.info = info
        self.triggers = None
        self.scheduler = scheduler

    def init_task_id(self):
        self.triggers = self.info['schedule']['triggers']
        # 通过伪随机码创造ID
        task_id = "{}-{}".format(self.triggers, uuid.uuid4().hex)
        return task_id

    # 创建一个新的任务
    # 这个任务默认是新任务
    def add_new_task(self):
        # 立即执行任务
        print("执行任务")
        func = __name__ + ":" + "exe_task"
        self.info["task_id"] = self.init_task_id()  # 从self.info 里面看有没有task_id   逻辑改一下
        if self.triggers == 'date':
            job = self.scheduler.add_job(func=func, trigger=self.triggers, run_date=datetime.datetime.now(),
                                         id=self.info["task_id"], max_instances=10,
                                         kwargs={"params": self.info,
                                                 "id": self.info["task_id"]})  # kwargs表示向函数里func里传参
            print(self.scheduler.get_jobs())
        # 定时任务以后再说
        elif self.triggers == 'interval':
            self.scheduler.add_job(func=func, trigger=self.triggers, seconds=180, id=self.info["task_id"],
                                   replace_existing=True,
                                   kwargs={"params": self.info, "id": self.info["task_id"]})
            print(self.scheduler.get_jobs())
        #
        #     # elif self.triggers == 'cron':
        # #     self.scheduler.add_job(func=task.create_task(), trigger=self.triggers, year=self.year, month=self.month,
        # #                            week=self.week, day=self.day, hour=self.hour, minute=self.minute)

    def finished_to_run(self):
        func = __name__ + ":" + "exe_task"
        if self.info['state'] != "finished":
            return "ERROR!"
        elif self.scheduler.get_job(id=(self.info['task_id'])):
            return "The task is running!"
        else:
            params = Schedule_History.query.filter(id=self.info['task_id'])['params']
            if self.triggers == 'date':
                job = self.scheduler.add_job(func=func, trigger=self.triggers, run_date=datetime.datetime.now(),
                                             id=self.info["task_id"], max_instances=10,
                                             kwargs={"params": params,
                                                     "id": self.info["task_id"]})
        self.info['state'] = "run"
        data = dict(
            task_id=self.info["task_id"],
            state=self.info['state']
        )
        return data

    def run_to_pause(self):
        if self.info['state'] != "running":
            print("state error")
            return
        elif not self.scheduler.get_job(id=self.info['task_id']):
            print("The Task is not running!")
        else:
            self.scheduler.pause_job(id=self.info['task_id'])
            self.info['state'] = "pause"
            data = dict(
                task_id=self.info["task_id"],
                state=self.info['state']
            )
            return data

    def pause_to_run(self):
        if self.info['state'] != "pause":
            print("state error")
            return
        elif not self.scheduler.get_job(id=self.info['task_id']):
            print('The Task isn\'t exist')
        else:
            self.scheduler.resume_job(id=self.info['task_id'])
            self.info['state'] = "run"
            data = dict(
                task_id=self.info["task_id"],
                state=self.info['state']
            )
            return data

    def delete_task(self):
        task_id = self.info['task_id']
        self.scheduler.remove_job(job_id=task_id)
        print("success delete")

    def state_change(self):
        if self.info['state'] == "pause":
            self.pause_to_run()
        elif self.info['state'] == "run":
            self.run_to_pause()
        elif self.info['state'] == "finished":
            self.finished_to_run()


def exe_task(params, id):
    print(params)
    create_time = datetime.datetime.now()
    print(create_time)
    task = Task(info=params)
    scan_report = task.create_task()
    use_report(scan_report)
    end_time = datetime.datetime.now()
    print(end_time)

    if params['schedule']['triggers'] == 'date':
        add_schedule_history(id=id, create_time=create_time, scan_report=scan_report, end_time=end_time, params=params)

# 增删改查    定时任务的暂停，启动  已经完成的再运行一遍
# task_id 创建时间 完成时间 info参数 scan_report
