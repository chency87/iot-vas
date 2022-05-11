from app.backend.controller.scan.core import Scan
import nmap
import masscan


def test():
    sc = Scan(ip='198.53.49.46-50', ports='161', scan_argument='-sU', script_name='snmp*')
    result = sc.scan()
    print(result)
    return result
print('hello')
test()


