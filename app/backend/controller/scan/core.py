import nmap
import masscan


# 你是API的定制者，是你来设置端口参数的格式，让别人去匹配！
class Scan(object):
    def __init__(self, ip, ports=None, scan_argument=None, script_name=None):
        """
        param ip 我们要扫描的ip
        type: ip string

        param ports 扫描的目的端口
        type: ports string

        param scan_argument 扫描参数
        type: argument string

        paran script_name 扫描脚本
        type：script_name string   exc:"banner.nse"
        """
        self.ip = ip
        self.ports = ports
        self.scan_argument = scan_argument  # 扫描参数：例如-sU，-sT
        self.script_name = ' --script=' + script_name  # 使用哪种脚本
        self.nm = nmap.PortScanner()  # 创建nmap的Scanner类
        self.ms = masscan.PortScanner()  # 创建masscan的Scanner类
        self.results = None

    # 工具函数
    def get_ip(self, result):
        self.ip = list(result['scan'].keys())  # 将扫描的到的出来的ip地址赋值给self.ip
        return self.ip

    # 使用masscan检测开放的端口
    def port_decetion(self, max_rate='10000'):
        """
        Method which uses masscan to dectect the open ports if ports=None

        param result masscan扫描的结果
        type result dict

        :param hosts: string for hosts as masscan use it 'scanme.masscan.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as masscan use it '22,53,110,143-4564'
        """
        arg = '--max-rate ' + max_rate
        result = self.ms.scan(hosts=self.ip, ports=self.ports, arguments=arg)
        self.ports = list(result['scan'][self.ip]['tcp'].keys())
        return self.ports

    # 基本检测 无论什么扫描都会调用一次
    def basic_detection(self):
        """
        Method which detect the service
        param results: os与sev
        type results dict {ip:{"OS":"windows10",port{ service: ,snmp-info: }}
        """
        # 将os结果插入字典
        self.results = {}

        result = self.nm.scan(hosts=self.ip,
                              arguments='-A ' + self.scan_argument + self.script_name)  # 调用nmap执行-A扫描操作系统和os
        self.ip = list(result['scan'].keys())

        for ip in self.ip:
            self.results[ip] = {}
            self.results[ip]['os'] = result["scan"][ip]['osmatch'][0]['name']  # 从返回值里通过切片提取出操作系统版本
            self.results[ip]['vendor'] = result['scan'][ip]['vendor']  # 从返回值里通过切片提取出厂商
            self.results[ip]['hostname'] = result['scan'][ip]['hostnames']  # 从返回值里提取hostnames

        # 将端口服务信息插入字典
        if self.scan_argument == '-sU':
            connect = 'udp'
        else:
            connect = 'tcp'
        for ip in self.ip:
            if self.ports is None:
                self.ports = self.port_decetion()
                for port in self.ports:
                    self.results[ip][port] = {}
                    self.results[ip][port]['service_name'] = result['scan'][ip][connect][int(port)]['name']
            else:
                ports = list(self.ports)  # 这里ports应该是字符串，要把他转换成列表
                for port in ports:
                    self.results[ip][port] = {}
                    self.results[ip][port]['service_name'] = result['scan'][ip][connect][int(port)]['name']
        return result

    # 脆弱性信息获取
    def vul_detection(self, result):
        cve = {}  # 存储cve的字典，key是端口 value是该端口的cve信息
        for ip in self.ip:
            for port in self.ports:
                self.results[ip][port]['cve'] = result['scan'][self.ip]['tcp'][int(port)]['script']['vulscan']

    # snmp信息获取
    def snmp_info(self, result):
        for ip in self.ip:
            for port in self.ports:
                self.results[ip][port]['snmp-interfaces'] = result['scan'][ip]['udp'][port]['script'][
                    'snmp-interfaces']
                self.results[ip][port]['snmp-sysdescr'] = result['scan'][ip]['udp'][port]['script'][
                    'snmp-sysdescr']
                # snmp协议id暂时没找到

    def scan(self):
        if self.ports is None:
            self.port_decetion()

        # result 是完整的结果，self.result是要最终我们要的结果
        result = self.basic_detection()

        # 根据脚本将信息添加到 self.result里的信息
        if self.script_name == 'vulscan':
            self.vul_detection(result=result)
        elif self.script_name == 'snmp*':
            self.snmp_info(result=result)