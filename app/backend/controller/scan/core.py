import nmap
import masscan
import re


# 你是API的定制者，是你来设置端口参数的格式，让别人去匹配！
class Scan(object):
    def __init__(self, ip, ports=None, scan_argument=None, script_argument=None, sacn_rate=None):
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
        self.script_argument = script_argument  # 使用哪种脚本
        self.nm = nmap.PortScanner()  # 创建nmap的Scanner类
        self.ms = masscan.PortScanner()  # 创建masscan的Scanner类
        self.results = {}
        self.scan_rate = '--max-rate ' + str(sacn_rate)

    # 工具函数
    def get_ip(self, result):
        ips = list(result['scan'].keys())  # 将扫描的到的出来的ip地址赋值给self.ip
        return ips


    # 使用masscan检测开放的端口
    def port_decetion(self):
        """
        Method which uses masscan to dectect the open ports if ports=None

        param result masscan扫描的结果
        type result dict

        :param hosts: string for hosts as masscan use it 'scanme.masscan.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as masscan use it '22,53,110,143-4564'
        """
        # 如果扫描参数里有-sU 则使用udp扫描
        try:
            port = []
            if re.search('-sU', self.scan_argument):

                ports = 'U:' + self.ports
                result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
                ips = list(result['scan'].keys())
                for ip in ips:
                    port = list(result['scan'][ip]['udp'].keys())

            # tcp 扫描
            ports = 'T:' + self.ports
            result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
            # 将扫描的ip列表化
            ips = list(result['scan'].keys())
            for ip in ips:
                port = port + list(result['scan'][ip]['tcp'])
            open_ports = [str(i) for i in port]
            ports = ','.join(open_ports)
            return ports  # 这里ports要转换成字符串，后面basic_dection 还要用
        except:
            print("network is unreachable")

    # 基本检测 无论什么扫描都会调用一次
    def basic_detection(self, ports=None):
        """
        Method which detect the service
        """
        ##这里待会记得改一下，ports改成 self.ports
        if self.ports is None:
            ports = self.port_decetion()  # 如果用户没有提供端口，则需要用masscan扫描出来
        result = self.nm.scan(hosts=self.ip, ports=ports, arguments=self.scan_argument + ' ' + self.script_argument)
        print(result)
        return result

    # 为每个ip设一个字典
    def process_result(self, result):
        ips = self.get_ip(result)
        for ip in ips:
            self.results[ip] = {}
            self.results[ip]['tcp'] = {}
            self.results[ip]['udp'] = {}

    # 获取hostnames
    def get_hostnames(self, result):
        ips = self.get_ip(result)
        for ip in ips:
            self.results[ip]['hostnames'] = result['scan'][ip]['hostnames']

    def get_vender(self, result):
        ips = list(result['scan'].keys())
        for ip in ips:
            self.results[ip]['vendor'] = result['scan'][ip]['vendor']

    # 端口服务探测
    def service(self, result):
        ips = self.get_ip(result)
        for ip in ips:
            if 'tcp' in result['scan'][ip].keys():
                tcp_ports = list(result['scan'][ip]['tcp'].keys())
                for t_port in tcp_ports:
                    self.results[ip]['tcp'][int(t_port)] = {}
                    self.results[ip]['tcp'][int(t_port)]['service'] = result['scan'][ip]['tcp'][int(t_port)]['name']
            if 'udp' in result['scan'][ip].keys():
                udp_ports = list(result['scan'][ip]['udp'].keys())
                for u_port in udp_ports:
                    self.results[ip]['udp'][int(u_port)] = {}
                    self.results[ip]['udp'][int(u_port)]['service'] = result['scan'][ip]['udp'][int(u_port)]['name']

    # 脆弱性信息获取
    def vul_detection(self, result):
        cve = {}  # 存储cve的字典，key是端口 value是该端口的cve信息
        ips = self.get_ip(result)
        for ip in ips:
            if 'tcp' in result['scan'][ip].keys():
                tcp_ports = list(result['scan'][ip]['tcp'].keys())
                for t_port in tcp_ports:
                    if 'vulscan' in result['scan'][ip]['tcp'][int(t_port)]['script']:
                        self.results[ip][t_port]['cve'] = result['scan'][ip]['tcp'][int(t_port)]['script'][
                            'vulscan']
            if 'udp' in result['scan'][ip].keys():
                udp_ports = list(result['scan'][ip]['udp'].keys())
                for u_port in udp_ports:
                    if 'vulscan' in result['scan'][ip]['tcp'][int(u_port)]['script']:
                        self.results[ip][u_port]['cve'] = result['scan'][ip]['tcp'][int(u_port)]['script'][
                            'vulscan']

    # snmp信息获取
    def snmp_info(self, result):
        ips = self.get_ip(result)
        for ip in ips:
            u_ports = list(result['scan'][ip]['udp'].keys())
            t_ports = list(result['scan'][ip]['tcp'].keys())
            if 161 in u_ports:
                if 'snmp-interfaces' in result['scan'][ip]['udp'][161]['script']:
                    self.results[ip]['udp'][161]['snmp-interfaces'] = result['scan'][ip]['udp'][161]['script']['snmp-interfaces']
                if 'snmp-sysdescr' in result['scan'][ip]['udp'][161]['script']:
                    self.results[ip]['udp'][161]['snmp-sysdescr'] = result['scan'][ip]['udp'][161]['script']['snmp-sysdescr']

    def get_result(self):
        return self.results
