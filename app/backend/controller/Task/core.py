from app.backend.controller.scan.core import Scan


# 示例结果


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

    # 定时任务包装
    def set_desc(self):
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
        #配置信息获取部分
        for config in configs:
            if config == 'service':
                sc.service(result=result)
            elif config == 'vul':
                sc.vul_detection(result=result)

        #脚本信息获取部分
        for script in self.script:
            if script == 'snmp-interfaces'or"snmp-sysdecsr":
                sc.snmp_info(result=result)
            elif script == 'vulscan/vulscan':
                sc.vul_detection(result=result)

        return sc.get_result()
