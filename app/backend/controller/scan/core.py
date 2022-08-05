import ast
import random

import nmap
import masscan
import re
import csv


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
        self.results = []
        self.scan_rate = "--max-rate " + str(sacn_rate)

    # 工具函数
    def get_ip(self, result):
        ips = list(result["scan"].keys())  # 将扫描的到的出来的ip地址赋值给self.ip
        return ips

    # 使用masscan检测开放的端口
    def port_decetion(self):
        """
        Method which uses masscan to dectect the open ports if ports=None

        param result masscan扫描的结果
        type result dict

        :param hosts: string for hosts as masscan use it "scanme.masscan.org" or "198.116.0-255.1-127" or "216.163.128.20/20"
        :param ports: string for ports as masscan use it "22,53,110,143-4564"
        """
        # 如果扫描参数里有-sU 则使用udp扫
        try:
            if re.search("-sU", self.scan_argument):
                ports = "U:1-65535"
                result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
                ips = list(result["scan"].keys())
                for ip in ips:
                    port = list(result["scan"][ip]["udp"].keys())

            # tcp 扫描
            ports = "T:1-65535"
            result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
            # 将扫描的ip列表化
            ips = list(result["scan"].keys())
            for ip in ips:
                port = port + list(result["scan"][ip]["tcp"])
            open_ports = [str(i) for i in port]
            ports = ",".join(open_ports)
            return ports  # 这里ports要转换成字符串，后面basic_dection 还要用
        except:
            print("network is unreachable.")
            return None

    # 基本检测 无论什么扫描都会调用一次
    def basic_detection(self):
        """
        Method which detect the service
        """
        print("star nmap_scan")

        if self.ports is None:
            ports = self.port_decetion()  # 如果用户没有提供端口，则需要用masscan扫描出来
        else:
            ports = self.ports
        result = self.nm.scan(hosts=self.ip, ports=ports,
                              arguments=self.scan_argument + " " + self.script_argument)
        print(result)
        return result

    # 为每个ip设一个字典
    def init_result(self, result):
        ips = self.get_ip(result)

        for i in range(len(ips)):
            self.results.append({})  # 往result里添加一个字典
            # 与端口无关的信息，请插入到这里
            self.results[i][ips[i]] = {}
            self.results[i][ips[i]]["OS"] = ""
            self.results[i][ips[i]]["vendor"] = ""
            self.results[i][ips[i]]["model_name"] = ""
            self.results[i][ips[i]]["firmware_version"] = ""
            self.results[i][ips[i]]["is_discontinued"] = "False"
            self.results[i][ips[i]]["cve_list"] = []
            self.results[i][ips[i]]["device_type"] = ""
            self.results[i][ips[i]]["firmware_infor"] = {"name": "", "version": "", "sha2": ""}
            # 与端口有关的信息，请插入到这里
            self.results[i][ips[i]]["tcp"] = []
            self.results[i][ips[i]]["udp"] = []

            tcp_ports = list(result["scan"][ips[i]]["tcp"].keys()) if "tcp" in result["scan"][ips[i]] else []

            udp_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []

            for j in range(len(tcp_ports)):
                self.results[i][ips[i]]["tcp"].append({})
                self.results[i][ips[i]]["tcp"][j]["port"] = tcp_ports[j]
            for j in range(len(udp_ports)):
                self.results[i][ips[i]]["udp"].append({})
                self.results[i][ips[i]]["udp"][j]["port"] = udp_ports[j]
        return self.results

    # 获取hostnames
    def get_hostnames(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            self.results[i][ips[i]]["hostnames"] = result["scan"][ips[i]]["hostnames"]

    # 获取厂商信息
    def get_vender(self, result):
        ips = list(result["scan"].keys())
        for i in range(len(ips)):
            self.results[i][ips[i]]["vendor"] = result["scan"][ips[i]]["vendor"]

    # 端口服务探测信息获取
    def service(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            if "tcp" in result["scan"][ips[i]].keys():
                tcp_ports = list(result["scan"][ips[i]]["tcp"].keys()) if "tcp" in result["scan"][ips[i]] else []
                for j in range(len(tcp_ports)):
                    self.results[i][ips[i]]["tcp"][j]["service"] = result["scan"][ips[i]]["tcp"][int(tcp_ports[j])][
                        "name"]
            if "udp" in result["scan"][ips[i]].keys():
                udp_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []
                for j in range(len(udp_ports)):
                    self.results[i][ips[i]]["udp"][j]["service"] = result["scan"][ips[i]]["udp"][int(udp_ports[j])][
                        "name"]

    def os_match(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            if "osmatch" in result["scan"][ips[i]]:
                self.results[i][ips[i]]["OS"] = result["scan"][ips[i]]["osmatch"][0]['name']
        # 设备类型探测
        device_type_list = []
        device_type = ""
        for i in range(len(ips)):
            if "osmatch" in result["scan"][ips[i]]:
                for j in range(len(result["scan"][ips[i]]["osmatch"])):
                    device_type_list.append(result["scan"][ips[i]]["osmatch"][j]["osclass"][0]["type"])
                device_type_list = list(set(device_type_list))  # 列表去重
                for k in range(len(device_type_list)):
                    device_type = "|" + device_type_list[k] + "|"
                self.results[i][ips[i]]["device_type"] = device_type
        print(device_type)

    # 脆弱性信息获取

    def vul_detection(self, result):
        cve = {}  # 存储cve的字典，key是端口 value是该端口的cve信息
        ips = self.get_ip(result)
        for i in range(len(ips)):
            if "tcp" in result["scan"][ips[i]].keys():
                tcp_ports = list(result["scan"][ips[i]]["tcp"].keys()) if "tcp" in result["scan"][ips[i]] else []
                for j in range(len(tcp_ports)):
                    if "script" in result["scan"][ips[i]]["tcp"][int(tcp_ports[j])] and "vulscan" in \
                            result["scan"][ips[i]]["tcp"][int(tcp_ports[j])]["script"]:
                        # cve = str.splitlines(result["scan"][ips[i]]["tcp"][int(tcp_ports[j])]["script"]["vulscan"])
                        cve = result["scan"][ips[i]]["tcp"][int(tcp_ports[j])]["script"]["vulscan"]
                        CVE_ID = re.findall('CVE-\\d{4}-\\d{1,5}', cve)  # 提取CVE编号
                        temp = []
                        for id in CVE_ID:  # 排除掉重复的CVE_ID
                            if id not in temp:
                                temp.append(id)
                        CVE_ID = temp
                        csv_reader = csv.reader(open('cvss.csv'))  # 读取cvss文件
                        CVE = {}
                        for line in csv_reader:
                            CVE[line[0]] = line[3]
                        CVE_CVSS = {}
                        for cve_id in CVE_ID:
                            print(cve_id)
                            CVE_CVSS[cve_id] = CVE.get(cve_id)
                        for k in range(len(CVE_ID)):
                            self.results[i][ips[i]]["cve_list"].append({})
                            self.results[i][ips[i]]["cve_list"][k]["cve_id"] = CVE_ID[k]
                            self.results[i][ips[i]]["cve_list"][k]["cvss"] = CVE_CVSS[CVE_ID[k]]

                        # cve = str.splitlines(result["scan"][ips[i]]["tcp"][int(tcp_ports[j])]["script"]["vulscan"])
                        # for k in range(len(cve)):
                        #     self.results[i][ips[i]]["cve_list"].append({})
                        #     self.results[i][ips[i]]["cve_list"][k]["cve_id"] = cve[k]
                        #     self.results[i][ips[i]]["cve_list"][k]["cvss"] = str(random.randint(1, 10))

            if "udp" in result["scan"][ips[i]].keys():
                udp_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []
                for j in range(len(udp_ports)):
                    if "vulscan" in result["scan"][ips[i]]["udp"][j]["script"]:
                        cve = str.splitlines(result["scan"][ips[i]]["udp"][int(udp_ports[j])]["script"]["vulscan"])
                        for k in cve:
                            self.results[i][ips[i]]["cve_list"].append({})
                            self.results[i][ips[i]]["cve_list"]["cve_id"] = k
                            self.results[i][ips[i]]["cve_list"]["cvss"] = str(random.randint(1, 10))
                        # cve = str.splitlines(result["scan"][ips[i]]["udp"][int(udp_ports[j])]["script"]["vulscan"])
                        # for k in cve:
                        #     self.results[i][ips[i]]["cve_list"].append({})
                        #     self.results[i][ips[i]]["cve_list"]["cve_id"] = k
                        #     self.results[i][ips[i]]["cve_list"]["cvss"] = str(random.randint(1, 10))

    # snmp信息获取，只在161端口
    def snmp_info(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            u_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []
            for j in range(len(u_ports)):
                # 如果扫描的结果里有161端口，而且nmap扫描的结果里有snmp-sysdescr的结果则赋值
                if self.results[i][ips[i]]["udp"][j]["port"] == 161 and "snmp-sysdescr" in \
                        result["scan"][ips[i]]["udp"][161]["script"]:
                    self.results[i][ips[i]]["udp"][j]["snmp-sysdescr"] = result["scan"][ips[i]]["udp"][161]["script"][
                        "snmp-sysdescr"]

    # banner 获取

    def get_banner(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            t_ports = list(result["scan"][ips[i]]["tcp"].keys())
            for j in range(len(t_ports)):
                # 获取ftp_banner
                if self.results[i][ips[i]]["tcp"][j]["port"] == 21 and "banner" in result["scan"][ips[i]]["tcp"][21][
                    "script"]:
                    self.results[i][ips[i]]["tcp"][j]["ftp_banner"] = \
                        result["scan"][ips[i]]["tcp"][21]["script"]["banner"]
                # 获取telnet_banner
                if self.results[i][ips[i]]["tcp"][j]["port"] == 23 and "banner" in result["scan"][ips[i]]["tcp"][23][
                    "script"]:
                    self.results[i][ips[i]]["tcp"][j]["port"]["telnet_banner"] = \
                        result["scan"][ips[i]]["tcp"][23]["script"]["banner"]

    def s7_info(self, result):
        print("s7-info:")
        ips = self.get_ip(result)
        for i in range(len(ips)):
            t_ports = list(result["scan"][ips[i]]["tcp"].keys())
            if 102 in t_ports and "script" in result["scan"][ips[i]]["tcp"][102] and "s7-info" in \
                    result["scan"][ips[i]]["tcp"][102]["script"]:
                self.results[i][ips[i]]["model_name"] = 's7'
                self.results[i][ips[i]]['vendor'] = 'Siemens'
                s7_info = str.splitlines(result["scan"][ips[i]]["tcp"][102]["script"]['s7-info'])
                self.results[i][ips[i]]["firmware_infor"]["name"] = s7_info[1]
                self.results[i][ips[i]]["firmware_infor"]["version"] = s7_info[3]



    def get_result(self):
        return self.results
