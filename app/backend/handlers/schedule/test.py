#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from datetime import datetime

std = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///opt/homebrew/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.92 scan initiated Fri Jan  7 21:57:00 2022 as: /opt/homebrew/bin/nmap -oX - -vvv -&#45;stats-every 1s -sV -Pn -&#45;script=melsecq-discover-udp.nse,cr3-fingerprint.nse,enip-info.nse,vulscan/vulscan.nse -&#45;script-args vulscandb=cve -p 80,4396,44818, 82.102.188.9 -->
<nmaprun scanner="nmap" args="/opt/homebrew/bin/nmap -oX - -vvv -&#45;stats-every 1s -sV -Pn -&#45;script=melsecq-discover-udp.nse,cr3-fingerprint.nse,enip-info.nse,vulscan/vulscan.nse -&#45;script-args vulscandb=cve -p 80,4396,44818, 82.102.188.9" start="1641621420" startstr="Fri Jan  7 21:57:00 2022" version="7.92" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="3" services="80,4396,44818"/>
<verbose level="3"/>
<debugging level="0"/>
<taskbegin task="NSE" time="1641621421"/>
<taskend task="NSE" time="1641621421"/>
<taskbegin task="NSE" time="1641621421"/>
<taskend task="NSE" time="1641621421"/>
<taskbegin task="Parallel DNS resolution of 1 host." time="1641621421"/>
<taskend task="Parallel DNS resolution of 1 host." time="1641621421"/>
<taskbegin task="Connect Scan" time="1641621421"/>
<taskend task="Connect Scan" time="1641621421" extrainfo="3 total ports"/>
<taskbegin task="Service scan" time="1641621421"/>
<taskprogress task="Service scan" time="1641621427" percent="0.00"/>
<taskprogress task="Service scan" time="1641621432" percent="0.00"/>
<taskprogress task="Service scan" time="1641621438" percent="0.00"/>
<taskprogress task="Service scan" time="1641621443" percent="0.00"/>
<taskprogress task="Service scan" time="1641621449" percent="0.00"/>
<taskprogress task="Service scan" time="1641621454" percent="0.00"/>
<taskprogress task="Service scan" time="1641621459" percent="0.00"/>
<taskprogress task="Service scan" time="1641621464" percent="0.00"/>
<taskprogress task="Service scan" time="1641621472" percent="0.00"/>
<taskprogress task="Service scan" time="1641621477" percent="0.00"/>
<taskprogress task="Service scan" time="1641621483" percent="0.00"/>
<taskprogress task="Service scan" time="1641621488" percent="0.00"/>
<taskprogress task="Service scan" time="1641621493" percent="0.00"/>
<taskprogress task="Service scan" time="1641621499" percent="0.00"/>
<taskprogress task="Service scan" time="1641621504" percent="0.00"/>
<taskprogress task="Service scan" time="1641621510" percent="0.00"/>
<taskprogress task="Service scan" time="1641621515" percent="0.00"/>
<taskprogress task="Service scan" time="1641621520" percent="0.00"/>
<taskprogress task="Service scan" time="1641621526" percent="0.00"/>
<taskprogress task="Service scan" time="1641621534" percent="0.00"/>
<taskprogress task="Service scan" time="1641621539" percent="0.00"/>
<taskprogress task="Service scan" time="1641621544" percent="0.00"/>
<taskprogress task="Service scan" time="1641621549" percent="0.00"/>
<taskprogress task="Service scan" time="1641621555" percent="0.00"/>
<taskprogress task="Service scan" time="1641621560" percent="0.00"/>
<taskprogress task="Service scan" time="1641621566" percent="0.00"/>
<taskprogress task="Service scan" time="1641621571" percent="0.00"/>
<taskprogress task="Service scan" time="1641621576" percent="0.00"/>
<taskprogress task="Service scan" time="1641621582" percent="0.00"/>
<taskprogress task="Service scan" time="1641621587" percent="100.00" remaining="0" etc="1641621587"/>
<taskend task="Service scan" time="1641621587" extrainfo="1 service on 1 host"/>
<taskbegin task="NSE" time="1641621587"/>
<taskprogress task="NSE" time="1641621587" percent="97.83" remaining="0" etc="1641621587"/>
<taskend task="NSE" time="1641621588"/>
<taskbegin task="NSE" time="1641621588"/>
<taskend task="NSE" time="1641621588"/>
<host starttime="1641621421" endtime="1641621588"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="82.102.188.9" addrtype="ipv4"/>
<hostnames>
<hostname name="82-102-188-9.orange.net.il" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="4396"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="fly" method="table" conf="3"/></port>
<port protocol="tcp" portid="44818"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="EtherNet-IP-2" method="probed" conf="10"/><script id="fingerprint-strings" output="&#xa;  TLSSessionReq: &#xa;    rando"><elem key="TLSSessionReq">&#xa;    rando</elem>
</script><script id="enip-info" output="&#xa;  Vendor: Rockwell Automation/Allen-Bradley (1)&#xa;  Product Name: 1769-L18ER/B LOGIX5318ER&#xa;  Serial Number: 0xd019bd19&#xa;  Device Type: Programmable Logic Controller (14)&#xa;  Product Code: 154&#xa;  Revision: 32.11&#xa;  Device IP: 192.168.0.10"><elem key="Vendor">Rockwell Automation/Allen-Bradley (1)</elem>
<elem key="Product Name">1769-L18ER/B LOGIX5318ER</elem>
<elem key="Serial Number">0xd019bd19</elem>
<elem key="Device Type">Programmable Logic Controller (14)</elem>
<elem key="Product Code">154</elem>
<elem key="Revision">32.11</elem>
<elem key="Device IP">192.168.0.10</elem>
</script></port>
</ports>
<times srtt="286846" rttvar="164519" to="944922"/>
</host>
<taskbegin task="NSE" time="1641621588"/>
<taskend task="NSE" time="1641621588"/>
<taskbegin task="NSE" time="1641621588"/>
<taskend task="NSE" time="1641621588"/>
<runstats><finished time="1641621588" timestr="Fri Jan  7 21:59:48 2022" summary="Nmap done at Fri Jan  7 21:59:48 2022; 1 IP address (1 host up) scanned in 167.14 seconds" elapsed="167.14" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
'''

os_scan6 = '''<?xml version="1.0"?>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 6.40-2 scan initiated Thu May  8 23:55:36 2014 as: nmap -O -vv -oX osscan.xml 192.168.1.0/24 -->
<nmaprun scanner="nmap" args="nmap -O -vv -oX osscan.xml 192.168.1.0/24" start="1399586136" startstr="Thu May  8 23:55:36 2014" version="6.40-2" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"/>
<verbose level="2"/>
<debugging level="0"/>
<taskbegin task="ARP Ping Scan" time="1399586136"/>
<taskend task="ARP Ping Scan" time="1399586139" extrainfo="255 total hosts"/>
<taskbegin task="Parallel DNS resolution of 255 hosts." time="1399586139"/>
<taskend task="Parallel DNS resolution of 255 hosts." time="1399586139"/>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.0" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.2" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.4" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.6" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.7" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.8" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.9" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.11" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.12" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.13" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.14" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.15" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.16" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.17" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.18" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.19" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.20" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.21" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.22" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.23" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.24" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.25" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.26" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.27" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.28" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.29" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.30" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.31" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.32" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.33" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.34" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.35" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.36" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.37" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.38" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.39" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.40" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.41" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.42" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.43" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.44" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.45" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.46" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.47" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.48" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.49" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.51" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.52" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.53" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.54" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.55" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.56" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.57" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.58" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.59" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.60" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.61" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.62" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.63" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.64" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.65" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.66" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.67" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.68" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.69" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.70" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.71" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.72" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.73" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.74" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.75" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.76" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.77" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.78" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.79" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.80" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.81" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.82" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.83" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.84" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.85" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.86" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.87" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.88" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.89" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.90" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.91" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.92" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.93" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.94" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.95" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.96" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.97" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.98" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.99" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.101" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.102" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.103" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.104" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.105" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.106" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.107" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.108" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.109" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.110" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.111" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.112" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.113" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.114" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.115" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.116" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.117" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.118" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.119" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.120" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.121" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.122" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.123" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.124" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.125" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.126" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.127" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.128" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.129" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.130" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.131" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.132" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.133" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.134" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.135" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.136" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.137" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.138" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.139" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.140" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.141" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.142" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.143" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.144" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.145" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.146" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.147" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.148" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.149" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.150" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.151" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.152" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.153" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.154" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.155" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.156" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.157" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.158" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.159" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.160" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.161" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.162" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.163" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.164" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.165" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.166" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.167" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.168" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.169" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.170" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.171" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.172" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.173" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.174" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.175" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.176" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.177" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.178" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.179" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.180" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.181" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.182" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.183" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.184" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.185" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.186" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.187" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.188" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.189" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.190" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.191" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.192" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.193" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.194" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.195" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.196" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.197" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.198" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.199" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.200" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.201" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.202" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.203" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.204" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.205" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.206" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.207" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.208" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.209" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.210" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.211" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.212" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.213" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.214" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.215" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.216" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.217" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.218" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.219" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.220" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.221" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.222" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.223" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.224" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.225" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.226" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.227" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.228" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.229" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.230" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.231" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.232" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.233" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.234" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.235" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.236" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.237" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.238" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.239" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.240" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.241" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.242" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.243" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.244" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.245" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.246" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.247" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.248" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.249" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.250" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.251" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.252" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.253" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.254" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.255" addrtype="ipv4"/>
</host>
<taskbegin task="Parallel DNS resolution of 1 host." time="1399586139"/>
<taskend task="Parallel DNS resolution of 1 host." time="1399586139"/>
<taskbegin task="SYN Stealth Scan" time="1399586139"/>
<taskend task="SYN Stealth Scan" time="1399586150" extrainfo="2000 total ports"/>
<host starttime="1399586136" endtime="1399586153"><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="6C:2E:85:19:AF:00" addrtype="mac" vendor="Sagemcom"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="994">
<extrareasons reason="resets" count="994"/>
</extraports>
<port protocol="tcp" portid="23"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="telnet" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="https" method="table" conf="3"/></port>
<port protocol="tcp" portid="992"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="telnets" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http-proxy" method="table" conf="3"/></port>
<port protocol="tcp" portid="8443"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="https-alt" method="table" conf="3"/></port>
</ports>
<os><portused state="open" proto="tcp" portid="23"/>
<portused state="closed" proto="tcp" portid="1"/>
<portused state="closed" proto="udp" portid="37463"/>
<osmatch name="Linux 2.6.13 (embedded)" accuracy="100" line="46590">
<osclass type="WAP" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="100"><cpe>cpe:/o:linux:linux_kernel:2.6.13</cpe></osclass>
</osmatch>
<osfingerprint fingerprint="OS:SCAN(V=6.40-2%E=4%D=5/8%OT=23%CT=1%CU=37463%PV=Y%DS=1%DC=D%G=Y%M=6C2E85%&#xa;OS:TM=536BFD69%P=x86_64-apple-darwin10.8.0)SEQ(SP=C0%GCD=1%ISR=D1%TI=Z%CI=I&#xa;OS:%II=I%TS=7)OPS(O1=M5B4ST11NW1%O2=M5B4ST11NW1%O3=M5B4NNT11NW1%O4=M5B4ST11&#xa;OS:NW1%O5=M5B4ST11NW1%O6=M5B4ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16&#xa;OS:A0%W6=16A0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M5B4NNSNW1%CC=N%Q=)T1(R=Y%DF=Y%T=4&#xa;OS:0%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M&#xa;OS:5B4ST11NW1%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF&#xa;OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=&#xa;OS:%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%&#xa;OS:IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)&#xa;"/>
</os>
<uptime seconds="1988763" lastboot="Tue Apr 15 23:29:50 2014"/>
<distance value="1"/>
<tcpsequence index="192" difficulty="Good luck!" values="1E97A4C2,1F15428A,1E9E6FE0,1F0EA94F,1EAED5F3,1F536969"/>
<ipidsequence class="All zeros" values="0,0,0,0,0,0"/>
<tcptssequence class="100HZ" values="BDA9B76,BDA9B80,BDA9B8B,BDA9B95,BDA9BA1,BDA9BAC"/>
<times srtt="11283" rttvar="12665" to="100000"/>
</host>
<host starttime="1399586136" endtime="1399586153"><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.5" addrtype="ipv4"/>
<address addr="00:1F:3C:87:66:50" addrtype="mac" vendor="Intel Corporate"/>
<hostnames>
</hostnames>
<ports><extraports state="filtered" count="998">
<extrareasons reason="no-responses" count="998"/>
</extraports>
<port protocol="tcp" portid="2869"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="icslap" method="table" conf="3"/></port>
<port protocol="tcp" portid="5357"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="wsdapi" method="table" conf="3"/></port>
</ports>
<os><portused state="open" proto="tcp" portid="2869"/>
<osmatch name="Microsoft Windows Server 2008 Beta 3" accuracy="100" line="52037">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="100"><cpe>cpe:/o:microsoft:windows_server_2008::beta3</cpe></osclass>
</osmatch>
<osmatch name="Microsoft Windows 7 Professional" accuracy="100" line="52938">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="7" accuracy="100"><cpe>cpe:/o:microsoft:windows_7::-:professional</cpe></osclass>
</osmatch>
<osmatch name="Microsoft Windows Phone 7.5" accuracy="100" line="54362">
<osclass type="phone" vendor="Microsoft" osfamily="Windows" osgen="Phone" accuracy="100"><cpe>cpe:/o:microsoft:windows</cpe></osclass>
</osmatch>
<osmatch name="Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7" accuracy="100" line="54897">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="Vista" accuracy="100"><cpe>cpe:/o:microsoft:windows_vista::-</cpe><cpe>cpe:/o:microsoft:windows_vista::sp1</cpe></osclass>
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="100"><cpe>cpe:/o:microsoft:windows_server_2008::sp1</cpe></osclass>
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="7" accuracy="100"><cpe>cpe:/o:microsoft:windows_7</cpe></osclass>
</osmatch>
<osmatch name="Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008" accuracy="100" line="55210">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="Vista" accuracy="100"><cpe>cpe:/o:microsoft:windows_vista::sp2</cpe></osclass>
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="7" accuracy="100"><cpe>cpe:/o:microsoft:windows_7::sp1</cpe></osclass>
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="100"><cpe>cpe:/o:microsoft:windows_server_2008</cpe></osclass>
</osmatch>
<osfingerprint fingerprint="OS:SCAN(V=6.40-2%E=4%D=5/8%OT=2869%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=001F3C%TM=5&#xa;OS:36BFD69%P=x86_64-apple-darwin10.8.0)SEQ(SP=101%GCD=1%ISR=108%TI=I%TS=7)O&#xa;OS:PS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4N&#xa;OS:W8ST11%O6=M5B4ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)E&#xa;OS:CN(R=Y%DF=Y%TG=80%W=2000%O=M5B4NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%TG=80%S=O%A=S+&#xa;OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)U1(R=N)IE(R=N)&#xa;"/>
</os>
<uptime seconds="213708" lastboot="Tue May  6 12:34:05 2014"/>
<distance value="1"/>
<tcpsequence index="257" difficulty="Good luck!" values="500D7F3D,4032B07A,E1E0C56,4859A528,A50E9523"/>
<ipidsequence class="Incremental" values="3B5D,3B5F,3B60,3B61,3B62"/>
<tcptssequence class="100HZ" values="14616CE,14616D8,14616E3,14616EE,14616FA"/>
<times srtt="37351" rttvar="40135" to="197891"/>
</host>
<taskbegin task="SYN Stealth Scan" time="1399586153"/>
<taskend task="SYN Stealth Scan" time="1399586157" extrainfo="1000 total ports"/>
<host starttime="1399586153" endtime="1399586159"><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="192.168.1.3" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="filtered" count="997">
<extrareasons reason="no-responses" count="997"/>
</extraports>
<port protocol="tcp" portid="88"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="kerberos-sec" method="table" conf="3"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ms-wbt-server" method="table" conf="3"/></port>
<port protocol="tcp" portid="5900"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="vnc" method="table" conf="3"/></port>
</ports>
<os><portused state="open" proto="tcp" portid="88"/>
<osmatch name="Apple Mac OS X 10.8 (Mountain Lion) (Darwin 12.0.0)" accuracy="100" line="5975">
<osclass type="general purpose" vendor="Apple" osfamily="Mac OS X" osgen="10.8.X" accuracy="100"><cpe>cpe:/o:apple:mac_os_x:10.8</cpe></osclass>
</osmatch>
<osmatch name="Apple Mac OS X 10.8 - 10.8.1 (Mountain Lion) (Darwin 12.0.0 - 12.1.0) or iOS 5.0.1" accuracy="100" line="6014">
<osclass type="general purpose" vendor="Apple" osfamily="Mac OS X" osgen="10.8.X" accuracy="100"><cpe>cpe:/o:apple:mac_os_x:10.8</cpe></osclass>
<osclass type="phone" vendor="Apple" osfamily="iOS" osgen="5.X" accuracy="100"><cpe>cpe:/o:apple:iphone_os:5</cpe></osclass>
<osclass type="media device" vendor="Apple" osfamily="iOS" osgen="5.X" accuracy="100"><cpe>cpe:/o:apple:iphone_os:5</cpe></osclass>
</osmatch>
<osfingerprint fingerprint="OS:SCAN(V=6.40-2%E=4%D=5/8%OT=88%CT=%CU=%PV=Y%DS=0%DC=L%G=N%TM=536BFD6F%P=x&#xa;OS:86_64-apple-darwin10.8.0)SEQ(SP=105%GCD=1%ISR=104%TI=RD%TS=A)OPS(O1=M3FD&#xa;OS:8NW4NNT11SLL%O2=M3FD8NW4NNT11SLL%O3=M3FD8NW4NNT11%O4=M3FD8NW4NNT11SLL%O5&#xa;OS:=M3FD8NW4NNT11SLL%O6=M3FD8NNT11SLL)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W&#xa;OS:5=FFFF%W6=FFFF)ECN(R=Y%DF=Y%TG=40%W=FFFF%O=M3FD8NW4SLL%CC=N%Q=)T1(R=Y%DF&#xa;OS:=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A&#xa;OS:=Z%F=R%O=%RD=0%Q=)U1(R=N)IE(R=N)&#xa;"/>
</os>
<uptime seconds="1026246" lastboot="Sun Apr 27 02:51:53 2014"/>
<distance value="0"/>
<tcpsequence index="261" difficulty="Good luck!" values="81850B90,7E7E7889,50987AD7,2AE07591,8C091D47,8DC681F7"/>
<ipidsequence class="Randomized" values="C313,1C42,329,53B2,9942,734E"/>
<tcptssequence class="1000HZ" values="3D2B3FB2,3D2B401D,3D2B4088,3D2B40EA,3D2B414D,3D2B41B0"/>
<times srtt="175" rttvar="350" to="100000"/>
</host>
<runstats><finished time="1399586159" timestr="Thu May  8 23:55:59 2014" elapsed="24.43" summary="Nmap done at Thu May  8 23:55:59 2014; 256 IP addresses (3 hosts up) scanned in 24.43 seconds" exit="success"/><hosts up="3" down="253" total="256"/>
</runstats>
</nmaprun>

'''


# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options, safe_mode=False)
    rc = nmproc.run()  # sudo_run(run_as="root")
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
        nmap_report.version,
        nmap_report.started))

    for host in nmap_report.hosts:

        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                str(serv.port),
                serv.protocol,
                serv.state,
                serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
            # get_item(serv)
            print(serv.scripts_results)
        print(host.scripts_results)
    print(nmap_report.summary)


def parse_nmap_stdout(stdout):
    report = NmapParser.parse_fromstring(stdout)
    host_dict = {
        'total': report.hosts_total,
        'up': report.hosts_up,
        'down': report.hosts_down,
        'online_host_list': []
    }
    service_lists = []
    for host in report.hosts:
        if host.is_up():
            online_host_list, host_service_list = store_reportitems(host)
            host_dict['online_host_list'].append(online_host_list)
            service_lists.extend(host_service_list)
    # print(len(service_lists))
    # print(service_lists)

    print(host_dict)


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
    service_list = []
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
                'cpe': {
                    'description': '',
                    'cpelist': []
                }
            }
            for osc in osm.osclasses:
                os_dict['cpe']['description'] = osc.description
                for cpe in osc.cpelist:
                    os_dict['cpe']['cpelist'].append(cpe.cpestring)
            os_match_list.append(os_dict)
    return os_match_list


def get_item(nmap_service):
    service_keys = ["port", "protocol", "state"]
    ritems = []
    jservice = {}
    for skey in service_keys:
        jservice[skey] = getattr(nmap_service, skey)
    jservice["type"] = "port-scan"
    jservice["service"] = nmap_service.service
    jservice["service-banner"] = nmap_service.banner

    for _serv_cpe in nmap_service.cpelist:
        print("        CPE: {0}".format(_serv_cpe.cpestring))

    for nse_item in nmap_service.scripts_results:
        jnse = {}
        for skey in service_keys:
            jnse[skey] = getattr(nmap_service, skey)
        jnse["type"] = "nse-script"
        jnse["nse-service"] = nse_item["id"]
        jnse["service-fingerprint"] = nse_item["output"]
        jnse.update(nse_item["elements"])
        jservice.update(jnse)
    jservice["service"] = nmap_service.service
    ritems.append(jservice)
    return ritems


if __name__ == "__main__":
    # -oX - -vvv -&#45;stats-every 1s -sV -Pn -&#45;script=melsecq-discover-udp.nse,cr3-fingerprint.nse,enip-info.nse,vulscan/vulscan.nse -&#45;script-args vulscandb=cve -p 80,4396,44818

    # -sV  -Pn  --script=enip-info.nse,vulscan/vulscan.nse --script-args vulscandb=cve -p 80,44818,3306,
    # -sV --script=enip-info.nse,vulscan/vulscan.nse --script-args vulscandb=cve -Pn -p 80,4396,44818

    # report = do_scan("82.102.188.9", "-sV  -Pn -O --script=enip-info.nse,vulscan/vulscan.nse --script-args vulscandb=cve -p 80,44818,3306,")
    # report = NmapParser.parse_fromfile('/Users/chenchunyu/Documents/workspace/sb-admin-2-python-master/app/backend/handlers/schedule/test.xml')
    # report = NmapParser.parse_fromstring(std)
    # if report:
    #     print_scan(report)
    # else:
    #     print("No results returned")

    parse_nmap_stdout(os_scan6)
