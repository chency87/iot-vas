import json

from flask import jsonify, render_template, request
from app.backend.models.dao import dao
from . import extract_info
from . import core


@extract_info.route('/extract_info', methods=['GET'])
def extract_info_get():
    try:
        core.add_iot_data()
        dao.add_update_weak_cert(None, 'port_scan_thor', '8F00B204E9800998', 'A215D1EF529FC876', 'FSA', 'SCI','1999.12.12','2011.04.14')
        dao.add_update_weak_cert(None, 'iot_tos', 'A0B923820DCC509A', 'E385D68D21F102AA', 'Kuris', 'SCI','1980.02.14','2017.8.14')
        dao.add_update_weak_cert(None, 'sc_koro', '9D4C2F636F067F89', 'A725214947B84B5A', 'oskm', 'COM', '2000.01.02','2010.06.13')

        dao.add_update_public_key(None, 'RSA', '2048')
        dao.add_update_public_key(None, 'RSA', '1024')
        dao.add_update_public_key(None, 'DES', '4096')
        dao.add_update_public_key(None, 'CC', '512')
        dao.add_update_public_key(None, 'DES', '256')
        dao.add_update_public_key(None, 'RSA', '128')
        dao.add_update_public_key(None, 'DES', '64')

        dao.add_update_default_account(None, 'af%sd24', '21A7548DE6260CF7', 'DES', 'spring', 1, 7, 'usa_logs')
        dao.add_update_default_account(None, '27', 'DB311BA4BC11CB26', 'SHA2', 'maven', 1, 7, 'cina')
        dao.add_update_default_account(None, 'col_vic', '39D17DFE89418452', 'Blowfish', 'flask', 1, 7, 'js_pan')

        dao.add_update_firmware_info(None, name='SA', version='24.0.1.8', sha2='6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6', release_date='2021.11.04', download_url='http://www.scthbz.cn/blog/_915205_303590.html')
        dao.add_update_firmware_info(None, name='Metavert ics device httpd', version='8.1.0.5', sha2='fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274', release_date='2021.08.04', download_url='https://b2b.baidu.com/ss?q=ics%E8%AE%BE%E5%A4%87&from=b2b_straight&srcid=5103&from_restype=elec&pi=baidu.b2b_straight.title')
        dao.add_update_firmware_info(None, name='PLC CJ2M', version='02.01', sha2='6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77', release_date='2020.08.07', download_url='https://rsonline.cn/web/p/plcs-programmable-logic-controllers/7462884/')
        dao.add_update_firmware_info(None, name='Omron CJ2M', version='1.11', sha2='5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb', release_date='Null', download_url='https://www.qc-engineering.com.sg/omron/cqm1h-scb41?gclid=EAIaIQobChMIy4vps_G--QIVk5NmAh0yJghuEAAYASAAEgLIofD_BwE')
        dao.add_update_firmware_info(None, name='Moxa NPort 5150', version='3.4 Build 11080114', sha2='6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680', release_date='Null', download_url='https://octopart.com/nport+5150-moxa-38902297?gclid=EAIaIQobChMI59jv9_K--QIVTpJmAh1kTAy_EAAYAiAAEgKKYvD_BwE')
        dao.add_update_firmware_info(None, name='PLC Mitsubishi', version='Q-series', sha2='7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6', release_date='Null', download_url='https://www.mitsubishielectric.com/fa/products/cnt/plc/index.html')
        dao.add_update_firmware_info(None, name='Bellwin power-misc', version='Null', sha2='59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889', release_date='2017', download_url='http://powersplitter.bellwin.com.tw/')
        dao.add_update_firmware_info(None, name='POPFile', version='pop3d', sha2='5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f', release_date='2022.08.11', download_url='https://popfile.en.softonic.com/?utm_source=SEM&utm_medium=paid&utm_campaign=EN_UK_DSA&gclid=EAIaIQobChMIk8Omyfu--QIVDhsrCh1M5AYrEAAYASAAEgJzI_D_BwE')
        dao.add_update_firmware_info(None, name='Dovecot imapd', version='Null', sha2='6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9', release_date='2022.07.29', download_url='https://docs.rackspace.com/support/how-to/dovecot-installation-and-configuration-on-centos/')
        dao.add_update_firmware_info(None, name='Openssh', version='7.6p1 Ubuntu 4ubuntu0.3', sha2='6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36', release_date='2019.03.04', download_url='https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4ubuntu0.3')

        dao.add_update_device_features_info_relation(None, '1', '1')
        dao.add_update_device_features_info_relation(None, '2', '2')
        dao.add_update_device_features_info_relation(None, '3', '3')
        dao.add_update_device_features_info_relation(None, '4', '4')
        dao.add_update_device_features_info_relation(None, '5', '5')
        dao.add_update_device_features_info_relation(None, '6', '6')
        dao.add_update_device_features_info_relation(None, '7', '7')
        dao.add_update_device_features_info_relation(None, '8', '8')
        dao.add_update_device_features_info_relation(None, '9', '9')
        dao.add_update_device_features_info_relation(None, '10', '10')
        dao.add_update_device_features_info_relation(None, '11', '11')
        dao.add_update_device_features_info_relation(None, '12', '12')
        dao.add_update_device_features_info_relation(None, '13', '13')

        dao.add_update_device_infor(None, manufacturer='Axis Communications AB', model_name='P3346',
                                    firmware_version='5.20', is_discontinued=True, cve_list='23,342,45,56,67,87,43,12,54,563,212',
                                    device_type='IP Camera', firmware_info='1', latest_firmware_info='1')
        dao.add_update_device_infor(None, manufacturer='ics', model_name='Endress+Hauser Fieldgate',
                                    firmware_version='FXA520',
                                    is_discontinued=True, cve_list='232,234,32,455,23,12,324,34,34,23,54,65,76,43,23,45,323,345,23,54,2343,45', device_type='gateway', firmware_info='2',
                                    latest_firmware_info='2')
        dao.add_update_device_infor(None, manufacturer='PLC', model_name='CJ2M', firmware_version='02.01',
                                    is_discontinued=True, cve_list='2343,322,3434,323,1222,2332,43,2323,2343,2332,1234,4564,2333,2345,3423,345,6545', device_type='CPU',
                                    firmware_info='3', latest_firmware_info='3')
        dao.add_update_device_infor(None, manufacturer='Omron', model_name='CJ2M', firmware_version='1.11',
                                    is_discontinued=True, cve_list='1112,1233,1412,1329,2313,2132,2343,5465,4533,4563,4532,4563,1233', device_type='CPU', firmware_info='4',
                                    latest_firmware_info='4')
        dao.add_update_device_infor(None, manufacturer='Moxa', model_name='NPort 5150',
                                    firmware_version='3.4 Build 11080114', is_discontinued=False,
                                    cve_list='435,124,657,223,123,32,87', device_type='serial-to-IP converter',
                                    firmware_info='5', latest_firmware_info='5')
        dao.add_update_device_infor(None, manufacturer='PLC', model_name='Mitsubishi', firmware_version='Q-series',
                                    is_discontinued=False, cve_list='234,435,654,345,234,456,245,78,213', device_type='CPU',
                                    firmware_info='6', latest_firmware_info='6')
        dao.add_update_device_infor(None, manufacturer='Bellwin', model_name='power-misc', firmware_version='Null',
                                    is_discontinued=False, cve_list='332,123,435,657,345,44,32,43,76,34,65,76',
                                    device_type='Server', firmware_info='7', latest_firmware_info='7')
        dao.add_update_device_infor(None, manufacturer='POPFile', model_name='pop3d', firmware_version='4vO',
                                    is_discontinued=False, cve_list='77,234,322,232,123,34,23,54,56,342,234,564',
                                    device_type='Server', firmware_info='8', latest_firmware_info='8')
        dao.add_update_device_infor(None, manufacturer='Dovecot', model_name='imapd', firmware_version='Null',
                                    is_discontinued=False, cve_list='344,456,768,23,465,345,345,235,234',
                                    device_type='Server', firmware_info='9', latest_firmware_info='9')
        dao.add_update_device_infor(None, manufacturer='NDT', model_name='OpenSSH',
                                    firmware_version='7.6p1 Ubuntu 4ubuntu0.3', is_discontinued=True,
                                    cve_list='23,454,656,22,34,546,23,34', device_type='Server', firmware_info='8,9,10',
                                    latest_firmware_info='10')

        dao.add_update_device_features(None, None, None, '220 211.22.103.167 CJ2M-EIP21 FTP server (FTP Version 1.11) ready.\n500 '': command not understood.', None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       """<html>

<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<style>
<!--{ font-family: Arial; font-size: 12pt }
-->
</style>
<title>Login</title>
</head>
<!-- Copyright 2002 Metavert Corporation www.metavert.com -->

<body bgcolor="#0000FF" text="#FFFFFF" LANGUAGE="javascript"
onload="return window_onload()">

<p align="right">&nbsp;</p>

<form method="POST" name="thisForm" action="../Setup.htm">
  <div align="center"><center><h3>Controller Status</h3>
  </center></div><div align="center"><center><table border="1" cellspacing="0" width="397">
    <tr>
      <td width="215">System time elapsed</td>
      <td width="174"><input type="text" readonly="true" name="ctElapse" size="10"></td>
    </tr>
    <tr>
      <td width="215">Firmware release date</td>
      <td width="174"><input type="text" readonly="true" name="ctVersion" size="17"></td>
    </tr>
    <tr>
      <td width="215">Serial number</td>
      <td width="174"><input type="text" readonly="true" name="ctMAC" size="18"></td>
    </tr>
  </table>
  </center></div><div align="center"><center><h3>Setup Login</h3>
  </center></div><div align="center"><center><table border="0" cellpadding="0"
  cellspacing="0" width="259">
    <tr>
      <td width="75">Password</td>
      <td width="184"><input type="password" name="ctPassword" size="16" tabindex="1">&nbsp; </td>
    </tr>
  </table>
  </center></div><div align="center"><center><p><input type="submit" value="Login"
  name="ctLogin"></p>
  </center></div>
</form>
</body>
</html>
<script ID="clientEventHandlersJS" LANGUAGE="javascript">
<!--
function set(sField,sValue)
{   document.thisForm[sField].value=sValue;
}  

function window_onload() {
   document.thisForm.ctPassword.focus();
set("ctElapse","659 02:05:31");
set("ctVersion","Dec 17 2003 12:36");
set("ctMAC","B2B-4687-3CD19179");
}
//-->
</script>
<!-- Memory 895052 -->""",None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       'PLC CJ2M',
                                       None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       'Omron CJ2M',
                                       None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       'Moxa NPort 5150',
                                       None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       '220 QnUDVCPU FTP server ready.',
                                       None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,
                                       """HTTP/1.0 200
Date: Tue, 09-Aug-2022 23:30:53 GMT
Server: BellWin/1.00.00
Connection: close
Cache-Control: no-cache, must-revalidate
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Set-Cookie: qsession=; expires=Mon, 08-Aug-2022 23:30:53 GMT
Content-Type: text/html

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

<head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="generator" content="HTML Tidy for Linux (vers 6 November 2007), see www.w3.org" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" >
<script language="javascript" type="text/javascript" src="js/language/title_eng.js"></script><script language="javascript" type="text/javascript" src="js/language/variant_eng.js"></script><script language="javascript" type="text/javascript" src="js/language/overmsg_eng.js"></script><script language="javascript" type="text/javascript">document.title=title_str;</script>
<script language="javascript" type="text/javascript">var Login_Error = 0;</script>
	<link rel="stylesheet" media="all" type="text/css" href="css/reset.css" />
	<link rel="stylesheet" media="all" type="text/css" href="css/ui.theme.css" />
	<link rel="stylesheet" media="all" type="text/css" href="css/body.css" />
	<link rel="stylesheet" media="all" type="text/css" href="css/login.css" />
	<link rel="stylesheet" media="all" type="text/css" href="css/jquery.cursorMessage.css" />
	<script language="javascript" type="text/javascript" src="js/jquery.js"></script>
	<script language="javascript" type="text/javascript" src="js/jquery.bgiframe.js"></script>  
	<script language="javascript" type="text/javascript" src="js/jquery.cursorMessage.js"></script>
	<script language="javascript" type="text/javascript" src="js/sprintf.js"></script>
	<script language="javascript" type="text/javascript" src="js/jquery.alphanumeric.js"></script>
	<script language="javascript" type="text/javascript" src="js/lib.js"></script>
	<script language="javascript" type="text/javascript" src="js/jquery.i18n.js"></script>
	<script language="javascript" type="text/javascript" src="js/jquery-ui.js"></script>
	<script language="javascript" type="text/javascript" src="js/login.js"></script>
	<meta name="generator" content="HTML Tidy for Linux (vers 6 November 2007), see www.w3.org" />
	<title>SmartPower</title>
</head>
<!--中-->
<body>
<div id="container">
    <div id="header" class="ui-state-hover ui-corner-all">
    	<div id="TopBar">
			<p id="banner_one">
	    		<img id="toplogo_1" alt="logo" />
			</p>
    	</div>
   	</div>
    <div id="client">
    	<div class="ui-widget-content ui-state-active ui-corner-all" id="Login_DIV_border">
			<div id="Login_DIV" class="ui-jqgrid ui-widget ui-widget-content ui-corner-all">
				<div class="ui-jqgrid-titlebar ui-widget-header ui-corner-tl ui-corner-tr ui-helper-clearfix">
					<p id="Login_Title"><span>Sign in</span></p>
				</div>
				<div class="frame_content">
					<div id="message"></div>
					<p class="field">
						<label for="auth_user"><span id="Login_user"></span>:&nbsp;</label>
						<input type="text" name="auth_user" id="auth_user" />
					</p>
					<p class="field">
						<label for="auth_passwd"><span id="Login_passwd"></span>:&nbsp;</label>
						<input type="password" name="auth_passwd" id="auth_passwd" />
					</p>
					<p id="Send_OK" class="actions ui-state-default ui-corner-all">
						<span id="Login_btnok_Str"></span>
					</p>
					<p class="cle"/>
				</div>
			</div>
		</div>
    </div>
    <div id="footer"></div>
</div>
</body>
</html>
""",None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None,'+OK POP3 POPFile (v4vO) server ready',None, None, None, None, None, None)
        dao.add_update_device_features(None, None, None, """* OK Waiting for authentication process to respond..
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot ready.
GET BAD Error in IMAP command received by server.
* BAD Error in IMAP command received by server.""", None, None, None, None,
                                       None, None)
        dao.add_update_device_features(None, None, None, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3', None, None, None, None,
                                       None, None)

        dao.add_update_default_account_relationship(None,  1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_default_account_relationship(None,  2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_default_account_relationship(None,  3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_default_account_relationship(None,  4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_default_account_relationship(None,  5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_default_account_relationship(None,  6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_default_account_relationship(None,  7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_default_account_relationship(None,  8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_default_account_relationship(None,  9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_default_account_relationship(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

        dao.add_update_crypto_key_relation(None,  1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_crypto_key_relation(None,  2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_crypto_key_relation(None,  3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_crypto_key_relation(None,  4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_crypto_key_relation(None,  5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_crypto_key_relation(None,  6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_crypto_key_relation(None,  7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_crypto_key_relation(None,  8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_crypto_key_relation(None,  9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_crypto_key_relation(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

        dao.add_update_weak_cert_relation(None, 1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_weak_cert_relation(None, 2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_weak_cert_relation(None, 3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_weak_cert_relation(None, 4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_weak_cert_relation(None, 5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_weak_cert_relation(None, 6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_weak_cert_relation(None, 7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_weak_cert_relation(None, 8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_weak_cert_relation(None, 9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_weak_cert_relation(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

        dao.add_update_config_issue_relation(None, 1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_config_issue_relation(None, 2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_config_issue_relation(None, 3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_config_issue_relation(None, 4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_config_issue_relation(None, 5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_config_issue_relation(None, 6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_config_issue_relation(None, 7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_config_issue_relation(None, 8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_config_issue_relation(None, 9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_config_issue_relation(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

        dao.add_update_expired_cert_relation(None, 1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_expired_cert_relation(None, 2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_expired_cert_relation(None, 3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_expired_cert_relation(None, 4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_expired_cert_relation(None, 5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_expired_cert_relation(None, 6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_expired_cert_relation(None, 7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_expired_cert_relation(None, 8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_expired_cert_relation(None, 9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_expired_cert_relation(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')

        dao.add_update_crypto_key_relation(None, 1, '6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6')
        dao.add_update_crypto_key_relation(None, 2, 'fb5c031fb18da2e23f6e72eac3344da37200fcfe292ea1dae8d09274')
        dao.add_update_crypto_key_relation(None, 3, '6b3472eeb4c24a0c95575f459de9f6e3bc419f4229b44f3a85312a77')
        dao.add_update_crypto_key_relation(None, 4, '5f5cb11c55a8ee842829bf8ec7d75f1a4c379d176f5459088c329fbb')
        dao.add_update_crypto_key_relation(None, 5, '6929026b7c9dc6718e28911801dc022d6a1353e75dd463b131205680')
        dao.add_update_crypto_key_relation(None, 6, '7e0376406e66fc3e9c01eb36dd8f19fdd58c0b6f677facb28c2ce0c6')
        dao.add_update_crypto_key_relation(None, 7, '59ce5a6b72f4e5dc15f793d2808af9edd6469968a80ea69ad241a889')
        dao.add_update_crypto_key_relation(None, 8, '5833e198dc69cccb304836785b684d9c2746907ee79018fc0009e61f')
        dao.add_update_crypto_key_relation(None, 9, '6944444e37a1b94b2473fc7b76cff86a3127cb4b5e8e5043d6484da9')
        dao.add_update_crypto_key_relation(None, 10, '6994471aac1ef3516ec6e503cd05003efa739d97b72883c4c2a6cf36')
    except Exception as e:
        print(e)
        return {'code': 404, 'error': 'Error'}
    return {'code': 20000, 'data': 'Success'}


@extract_info.route('/extract_info/extract_from_banner/', methods=['POST'])
def extract_from_banner():
    banner_text = request.form.get('banner')
    # JOSN转成字典
    return core.core_extract_banner(banner_text)
