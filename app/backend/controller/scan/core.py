import nmap
import masscan


class Scan(object):
    def __init__(self, ip, ports=None, argument=None):
        """
        param ip 我们要扫描的ip
        type: ip string

        param ports 扫描的目的端口
        type: ports string

        param argument 扫描参数
        type: argument string
        """
        self.ip = ip
        self.ports = ports
        self.argument = argument
        self.nm = nmap.PortScanner()  # 创建nmap的Scanner类
        self.ms = masscan.PortScanner()  # 创建masscan的Scanner类

    def get_arguments(self):
        if self.argument == "ping扫描":
            return "-sP"
        elif self.argument == "SYN扫描":
            return "-sS"
        elif self.argument =="TCP扫描":
            return "-sT"
        elif self.argument == "禁用ping扫描":
            return "-Pn"

    # 工具函数
    def get_result(self):
        result = self.nm.scan(hosts=self.ip, ports=self.ports, arguments=self.get_arguments())
        return result

    # def get_ports(self):
    #     result = self.get_result()
    #     ports_1 = list(result['scan'][self.ip]['tcp'].keys())
    #     ports_2 = [str(i) for i in ports_1]
    #     ports = ' '.join(ports_2)
    #     return ports

    # 使用masscan检测开放的端口
    def port_decetion(self):
        """
        Method which uses masscan to dectect the open ports if ports=None

        param result masscan扫描的结果
        type result dict

        param ports masscan扫描出来的开放端口
        type ports string  exc：”80 102 502 3306“
        """
        result = self.ms.scan(hosts=self.ip, ports=self.ports, arguments='--max-rate 100000 --banners')
        self.ports = list(result['scan'][self.ip]['tcp'].keys())
        return self.ports

    # 服务检测
    def sev_detection(self):
        """
        Method which detect the service
        param service_name 获取每个端口运行的服务
        """
        service_name = {}

        if self.ports is None:
            self.ports = self.port_decetion()
            result = self.get_result()
            for port in self.ports:
                service_name[port] = result['scan'][self.ip]['tcp'][int(port)]['name']
            return service_name
        else:
            result = self.get_result()
            ports = list(self.ports)  # 这里ports应该是字符串，要把他转换成列表
            for port in ports:
                service_name[port] = result['scan'][self.ip]['tcp'][int(port)]['name']
            return service_name

    # 操作系统检测
    def os_detection(self):
        result = self.nm.scan(hosts=self.ip, arguments='-O ' + self.argument)  # 调用nmap执行-O扫描操作系统
        os = result["scan"][self.ip]['osmatch'][0]['name']  # 从返回值里通过切片提取出操作系统版本
        return os

    # 脆弱性检测
    def vul_detection(self):
        cve = {}  # 存储cve的字典，key是端口 value是该端口的cve信息
        arg = self.get_arguments()
        result = self.nm.scan(hosts=self.ip, arguments=arg + ' --script = vulscan/vulscan.nse')
        ports = list(result['scan'][self.ip]['tcp'].keys())
        for port in ports:
            cve[port] = result['scan'][self.ip]['tcp'][int(port)]['script']['vulscan']
        return cve
