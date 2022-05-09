#    {'task_name': 'name', 'task_desc': 'desc', 'task_cmd': '2', 'task_engine': '2', 
#     'task_target_ip': 'localhost', 'task_func': ['sv', 'vulscan', 'os', 'ping'], 
#     'task_deps_db': ['cve'], 'task_deps_script': ['melsecq-discover-udp.nse', 'cr3-fingerprint.nse', 'enip-info.nse'], 
#     'task_trigger_type': 'cron', 'task_cron': '42 3 * * 5'}

from app.backend.handlers.plugins.core import get_abs_path
from app.backend.handlers.settings.core import PortInfoMana
from libnmap.process import NmapProcess

from libnmap.parser import NmapParser,NmapParserException
from datetime import datetime
from collections import Counter
import os

from app.backend.handlers.finger.core import add_update_device

class nmapScan:
    def init_nmap_options(args,db, deps, id):
        commons = '-sV ' if 'sv' in args else '-sP '
        commons += ' ' if 'os' in args else ''
        commons += '-Pn ' if 'ping' in args else ''
        script_commons = '--script='

        for item in deps:
            script_commons += os.path.join('upload', item) +','
            
        # print(script_commons)

        # script_commons = '--script=' + ','.join(map(str, deps))

        if 'vulscan' in args:
            script_commons += 'vulscan/vulscan.nse --script-args vulscandb='
            script_commons += ','.join(map(str, db))
        ports_options = nmapScan.init_nmap_port(id)
        return commons+' ' + script_commons +  ' ' + ports_options       

    def init_nmap_port(id):
        if id:
            ports = PortInfoMana.get_all_port_by_dict_id(id)
            port_commons = '-p '
            for item in ports:
                port_commons += str(item.port) +','
            return port_commons
        return None



def parse_nmap_stdout(stdout):
    report = NmapParser.parse_fromfile(stdout)
    
    
    host_dict = {
        'total' : report.hosts_total,
        'up'    : report.hosts_up,
        'down'  : report.hosts_down,
        'online_host_list' : []
        
    }
    service_lists = []
    for host in report.hosts:
        if host.is_up():
            online_host_list, host_service_list = store_reportitems(host)
            host_dict['online_host_list'].append(online_host_list)
            service_lists.extend(host_service_list)
    # print(host_dict)
    # print(service_lists)
    return host_dict, service_lists, report.startedstr, report.scan_type, report.elapsed, report.hosts_total

def store_reportitems(nmap_host):
    host_keys = [
        "starttime",
        "endtime",
        "address",
        "hostnames",
        "ipv4",
        "ipv6",
        "mac",
        "status",
    ]
    jhost = {}
    for hkey in host_keys:
        if hkey == "starttime" or hkey == "endtime":
            val = getattr(nmap_host, hkey)
            jhost[hkey] = datetime.fromtimestamp(int(val) if len(val) else 0).strftime("%d/%m/%y %S:%M:%H")
        else:
            jhost[hkey] = getattr(nmap_host, hkey)
            # get_os(nmap_host)
    # jhost.update(get_os(nmap_host))
    jhost['os'] = get_os(nmap_host)
    jhost['ports'] = len(nmap_host.services)
    service_list = []
    # print(jhost)
    
    for nmap_service in nmap_host.services:
        reportitems = get_item(nmap_service)

        for ritem in reportitems:
            ritem.update(jhost)
            service_list.append(ritem)
    # print(service_list)

    return jhost, service_list

def get_os(nmap_host):
    os_match_list = []
    if nmap_host.is_up() and nmap_host.os_fingerprinted:
        for osm in nmap_host.os.osmatches:
            os_dict = {
                'os': osm.name,
                'accuracy': osm.accuracy,
                'cpe' : {
                    'description': '',
                    'cpelist': []
                }
            }
            for osc in osm.osclasses:
                os_dict['cpe']['description'] = osc.description
                for cpe in osc.cpelist:
                    os_dict['cpe']['cpelist'].append(cpe.cpestring.replace('\n','\\\n'))
            os_match_list.append(os_dict)
    return os_match_list
def get_item(nmap_service):
    service_keys = ["port", "protocol", "state"]
    ritems = []
    jservice = {}
    for skey in service_keys:
        jservice[skey] = getattr(nmap_service, skey)

    # jservice['port'] = nmap_service
    jservice["type"] = "port-scan"
    jservice["service"] = nmap_service.service if nmap_service.service else ''
    jservice["service-banner"] = nmap_service.banner if nmap_service.banner else ''



    for nse_item in nmap_service.scripts_results:
        jnse = {}
        for skey in service_keys:
            jnse[skey] = getattr(nmap_service, skey)
        jnse["type"] = "nse-script"
        jnse["nse-service"] = nse_item["id"] if  nse_item["id"] else ''
        jnse["service-fingerprint"] = nse_item["output"].replace('\n', '\\\n') if  nse_item["output"] else ''
        jnse.update(nse_item["elements"])
        jservice.update(jnse)
    jservice["service"] = nmap_service.service
    if 'Vendor' in jservice.keys():
        vendor = jservice['Vendor'] if jservice['Vendor'] else ''
        product_name= jservice['Product Name'] if jservice['Product Name'] else ''
        serial_number= jservice['Serial Number'] if jservice['Serial Number'] else ''
        device_type= jservice['Device Type'] if jservice['Device Type'] else ''
        product_code= jservice['Product Code'] if jservice['Product Code'] else ''
        revision= jservice['Revision'] if jservice['Revision'] else ''
        service= jservice['service'] if jservice['service'] else ''
        protocol= jservice['protocol'] if jservice['protocol'] else ''
        device_ip = jservice['Device IP'] if jservice['Device IP'] else ''
        save_device_info_from_nse(vendor, product_name,serial_number,device_type, product_code,revision,service,protocol,device_ip)


    # if jservice['Vendor']:
    #     save_device_info_from_nse(jservice)
    ritems.append(jservice)
    return ritems


def save_device_info_from_nse(vendor, product_name,serial_number,device_type, product_code,revision,service,protocol,device_ip ):

    add_update_device(id = None, vendor = vendor, product_name = product_name, serial_number = serial_number, device_type = device_type,  product_code = product_code, revision = revision, service = service, protocol = protocol, device_ip = device_ip)