from app.backend.extensions import scheduler
from app.backend.models.models import Task
from app.backend.models.user import User
from app.backend.database.database import db
from app.backend.handlers import port_handler, schedule
from crontab import CronTab
from libnmap.parser import NmapParser
from libnmap.reportjson import ReportDecoder, ReportEncoder
from .template import dashboard_top, dashboard_scaninfo

from app.backend.handlers.logger.core import log_handler, LogActions, ActionResult
import json
from datetime import datetime
# from croniter import croniter
from collections import Counter
from .nmapscan import nmapScan, parse_nmap_stdout
from .public import exec_shell
import uuid
from app.conf.config import SCAN_XML_REPORT_FOLDER

# 三种触发方式
TRIGGER_BY_DATE = 'date'
TRIGGER_BY_INTERVAL = 'interval'
TRIGGER_BY_CRON = 'cron'
from libnmap.process import NmapProcess
import os
# from time import time
import time
ALLOWED_FUNC = ['exec_namp_scan', 'exec_namp_scan']
ALLOWED_FUNC_NAME = {
    'exec_namp_scan': '终端探测'
}


def exec_namp_scan(cmd, task_id):
    with scheduler.app.app_context():
        stdout = ''
        recode = 0
        target = cmd['task_target_ip']
        dict_id = cmd['task_target_ports']
        options = nmapScan.init_nmap_options(cmd['task_func'], cmd['task_deps_db'], cmd['task_deps_script'], dict_id)
        print(options)

        report_name = task_id + '-' + str(int(time.time())) + '.xml'
        report_name = os.path.join(SCAN_XML_REPORT_FOLDER, report_name)

        nmap_proc = NmapProcess(targets=target, options=options + ' -oX ' + report_name, safe_mode=False)
        rc = nmap_proc.run()
        if rc != 0:
            recode = 1
            stdout = nmap_proc.stderr
            print('Task exec failed {}'.format(stdout))
        else:
            stdout1 = nmap_proc.stdout
            stdout = report_name
            print('Task exec success {}'.format(report_name))

        data = dict(
            task_id=task_id,
            task_name=cmd['task_name'],
            task_desc=cmd['task_desc'],
            task_engine=cmd['task_engine'],
            task_trigger_type=cmd['task_trigger_type'],
            task_cron=cmd['task_cron'],
            status=True if recode == 0 else False,
            cmd=cmd['task_cmd'],
            stdout=stdout
        )
        new_log = Task(**data)

        try:
            db.session.add(new_log)
            db.session.commit()
            # print("任务日志写入成功")

        except Exception as e:
            print("任务日志写入失败 - %s" % e)
        if recode != 0:
            print('[Error] (%s---[%s]) failed' % (cmd, task_id))
            print(stdout)
            exit(407)
        return stdout


def init_exec_job(scheduler, **jobargs):
    func = __name__ + ':' + ALLOWED_FUNC[int(jobargs['task_cmd']) % len(ALLOWED_FUNC)]
    trigger_type = jobargs['task_trigger_type']
    id = "{}-{}".format(trigger_type, uuid.uuid4().hex)
    if trigger_type == TRIGGER_BY_DATE:
        run_date = jobargs['run_date']
        scheduler.add_job(func=func, id=id, kwargs={'cmd': jobargs, 'task_id': id}, trigger='date', run_date=run_date,
                          replace_existing=True)
        # print("添加一次性任务成功---[ %s ] " % id)
        return id
    elif trigger_type == TRIGGER_BY_INTERVAL:
        # start_date = start_date=None
        start_date = None
        end_date = None
        cron = jobargs['interval'].split(' ')
        print(start_date, end_date)
        scheduler.add_job(func=func, id=id, kwargs={'cmd': jobargs, 'task_id': id}, trigger='interval',
                          minutes=int(cron[1]), hours=int(cron[2]), days=int(cron[3]), weeks=int(cron[4]),
                          start_date=start_date, end_date=start_date, replace_existing=True)
        # print(cron)
        return id
        # second='*', 
    elif trigger_type == TRIGGER_BY_CRON:
        cron = jobargs['task_cron'].split(' ')
        cron_rel = dict(minute=cron[0], hour=cron[1], day=cron[2], month=cron[3], day_of_week=cron[4])
        scheduler.add_job(func=func, id=id, kwargs={'cmd': jobargs, 'task_id': id}, trigger='cron', **cron_rel,
                          replace_existing=True)
        return id
    else:
        pass


def get_current_jobs_list(job_id):
    try:
        if job_id == None:
            ret_list = scheduler.get_jobs()
        else:
            ret_list = [scheduler.get_job(job_id)]
        info_list = []
        for ret in ret_list:
            info = {
                'id': ret.id,
                'task_name': ret.kwargs.get('cmd')['task_name'],
                'next_run_time': ret.next_run_time.strftime('%m-%d-%Y, %H:%M') if ret.next_run_time != None else '',
                'cmd': ALLOWED_FUNC_NAME[
                           ALLOWED_FUNC[int(ret.kwargs.get('cmd')['task_cmd']) % len(ALLOWED_FUNC)]] + '(' +
                       ret.kwargs.get('cmd')['task_target_ip'] + ')',
                'func': ret.func_ref,
                'status': "Running" if ret.next_run_time != None else "Pause",
            }
            if TRIGGER_BY_CRON in str(ret.trigger):
                cron = {}
                for field in ret.trigger.fields:
                    cron[field.name] = str(field)
                cron_list = [cron['second'], cron['minute'], cron['hour'], cron['day'], cron['month'],
                             cron['day_of_week']]
                info['cron'] = ' '.join(cron_list)
            if TRIGGER_BY_DATE in str(ret.trigger):
                info['cron'] = ret.trigger.run_date
            if TRIGGER_BY_INTERVAL in str(ret.trigger):
                timedelta_seconds = ret.trigger.interval_length
                info['cron'] = str(ret.trigger.interval_length) + "s / run"
            print(info)
            info_list.append(info)
        return info_list
    except Exception as e:
        print(e)
        return None


def get_task_log_by_id(id):
    if id is None:
        return None
    tasks = Task.query.filter_by(task_id=id).order_by(Task.exe_time.desc()).all()
    print(tasks)

    res = []

    for item in tasks:
        up = 0
        total = 0
        if (item.stdout):
            try:
                report = NmapParser.parse_fromfile(item.stdout)
                up = report.hosts_up
                total = report.hosts_total
            except Exception:
                print(str(Exception))

        dic = {
            'id': item.id,
            'task_id': item.task_id,
            'exe_time': item.exe_time.strftime('%m/%d/%Y, %H:%M') if item.exe_time != None else 'UNKNOWN',
            'host_up': up,
            'host_total': total
        }
        res.append(dic)
    # print(res)
    return res


def get_report_by_id(id):
    if id is None:
        return None
    report = Task.query.filter_by(id=id).first()
    return report


def get_task_report_by_id(id):
    if id is None:
        return None
    # print(id)
    # print('===' * 50)
    stdout = get_report_by_id(id).stdout
    print(stdout)
    # print('---' * 50)
    host_dict, service_list, start, scan_type, elapsed, total = parse_nmap_stdout(stdout)

    device_count = 0
    port_list = []
    open_port_count = 0
    for serv in service_list:
        port_list.append(serv['service'])
        if serv['state'] == 'open':
            open_port_count += 1
        if serv['type'] == 'nse-script':
            device_count += 1
    # print(host_dict)
    # print(service_list)

    top = dashboard_top.format(host_dict['up'], '#hosts-service-tables', len(service_list), '#', open_port_count, '#',
                               device_count, '#')

    port_list_counter = Counter(port_list)
    most_common_port_list = port_list_counter.most_common(10)
    # print(service_list)

    scan_info = dashboard_scaninfo.format(start, scan_type, elapsed, total)

    # scan_info = {
    #     'time' : start,
    #     'type' : scan_type,
    #     'elapsed' : elapsed,
    #     'total' : total
    # }

    return top, host_dict, service_list, port_list_counter, most_common_port_list, scan_info


def get_task_report_by_stdout(stdout):
    nmap_report = NmapParser.parse_fromfile(stdout)

    open_port_count = 0
    total_port_count = 0
    filter_port_count = 0
    closed_port_count = 0
    os_count = 0
    host_list = []
    port_list = []

    # for nmap_host in nmap_report.hosts:
    for host in nmap_report.hosts:
        if host.is_up():
            total_port_count = total_port_count + len(host.get_ports())
            open_port_count = open_port_count + len(host.get_open_ports())
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address
            jhost = {
                'starttime': host.starttime,
                'endtime': host.endtime,  # datetime.fromtimestamp(int(  host.endtime) if len( host.endtime) else 0),
                'hostnames': tmp_host,
                'address': host.address,
                'status': host.status,
                'detected_service': len(host.services),
                'total_port': len(host.get_ports()),
                'scripts_results': host.scripts_results,
                'extraports_reasons': host.extraports_reasons,
                'os': get_os(host),
                'online_host_info': []
            }
            online_host_service_list = []
            for serv in host.services:
                port_list.append(port_handler.get_port_info_by_port(serv.port))
                serv_dict = {
                    'port': serv.port,
                    'protocol': serv.protocol,
                    'state': serv.state,
                    'service': serv.service,
                    'banner': serv.banner if len(serv.banner) else '',
                    'cpe_list': [_serv_cpe for _serv_cpe in serv.cpelist],
                }
                # print(serv.cpelist)
                online_host_service_list.append(serv_dict)
            jhost['online_host_info'] = online_host_service_list
            os_fingerprinted_list = []
            if host.os_fingerprinted:
                for osm in host.os.osmatches:
                    os_dict = {
                        'name': osm.name,
                        'accuracy': osm.accuracy,
                        'cpe_list': [cpe for cpe in osm.get_cpe()]
                    }
                    os_fingerprinted_list.append(os_dict)
                    os_count += 1
            jhost['os_fingerprinted'] = os_fingerprinted_list
            host_list.append(jhost)
    total_port_count = open_port_count + filter_port_count + closed_port_count
    port_list_counter = Counter(port_list)
    most_common_port_list = [[item[0], item[1]] for item in port_list_counter.most_common(10)]

    top = dashboard_top.format(nmap_report.hosts_up, '#', open_port_count, total_port_count, '#',
                               len(port_list_counter), '#', os_count, '#')

    scan_info = dashboard_scaninfo.format(nmap_report.startedstr, nmap_report.scan_type, nmap_report.elapsed,
                                          nmap_report.hosts_total)
    return top, scan_info, host_list, port_list_counter, most_common_port_list


def get_os(nmap_host):
    rval = {"vendor": "unknown", "product": "unknown"}
    if nmap_host.is_up() and nmap_host.os_fingerprinted:
        cpelist = nmap_host.os.os_cpelist()
        if len(cpelist):
            mcpe = cpelist.pop()
            rval.update(
                {"vendor": mcpe.get_vendor(), "product": mcpe.get_product()}
            )
    return rval


def store_reportitem(nmap_host, database, index):
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
    # address = nmap_host.address
    # jhost = {
    #     "starttime": nmap_host.starttime,
    #     "endtime": nmap_host.endtime,
    # }
    jhost = {}
    # for hkey in host_keys:
    #     if hkey == "starttime" or hkey == "endtime":
    #         # nmap_host.
    #         # val = getattr(nmap_host, hkey)
    #         val = None
    #         print(val)
    #         jhost[hkey] = datetime.fromtimestamp(int(val) if len(val) else 0)
    #     else:
    #         # jhost[hkey] = getattr(nmap_host, hkey)
    #         jhost[hkey] = ''

    #         print(jhost)
    #         print('---===='*10)

    # jhost.update({"country": get_geoip_code(nmap_host.address)})
    # jhost.update(get_os(nmap_host))
    print(jhost)
    print('===' * 50)
    # for nmap_service in nmap_host.services:
    #     reportitems = get_item(nmap_service)

    #     for ritem in reportitems:
    #         ritem.update(jhost)
    # database.index(index=index, doc_type="NmapItem", body=ritem)
    return jhost


def get_item(nmap_service):
    service_keys = ["port", "protocol", "state"]
    ritems = []

    # create report item for basic port scan
    jservice = {}
    for skey in service_keys:
        jservice[skey] = getattr(nmap_service, skey)
    jservice["type"] = "port-scan"
    jservice["service"] = nmap_service.service
    jservice["service-data"] = nmap_service.banner
    ritems.append(jservice)

    # create report items from nse script output
    for nse_item in nmap_service.scripts_results:
        jnse = {}
        for skey in service_keys:
            jnse[skey] = getattr(nmap_service, skey)
        jnse["type"] = "nse-script"
        jnse["service"] = nse_item["id"]
        jnse["service-data"] = nse_item["output"]
        ritems.append(jnse)

    return ritems
