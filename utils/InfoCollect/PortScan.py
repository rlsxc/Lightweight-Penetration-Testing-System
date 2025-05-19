import socket
import re
import concurrent.futures
import sys
import os
import logging
import time
import ipaddress
from urllib import parse
from django.core.exceptions import ValidationError

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 动态线程数
import multiprocessing
THREADNUM = min(64, multiprocessing.cpu_count() * 8)

# 指纹模式，修复括号配对问题
SIGNS = (

    b'xmpp|xmpp|^\<\?xml version=\'1.0\'\?\>',
    b'netbios|netbios|^\x79\x08.*BROWSE|^\x79\x08.\x00\x00\x00\x00|^\x05\x00\x0d\x03|^\x82\x00\x00\x00|\x83\x00\x00\x01\x8f',
    b'http|http|^HTTP/1.[0-1]',
    b'backdoor|backdoor|^500 Not Loged in|GET: command|sh: GET:|[a-z]*sh: .* command not found|^bash[$#]|^sh[$#]|^Microsoft Windows',
    b'db2|db2|.*SQLDB2RA',
    b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
    b'finger|finger|^\r\n\tLine\tUser|Line\tUser|Login name: |Login.*Name.*TTY.*Idle|^No one logged on|^\r\nWelcome|^finger:|^must provide username|finger: GET: ',
    b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61|^\x30\x32\x02\x01|^\x30\x33\x02\x01|^\x30\x38\x02\x01|^\x30\x84|^\x30\x45',
    b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',
    b'rdp|rdp|^\x03\x00\x00\x0b|^\x03\x00\x00\x11|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'rdp-proxy|rdp-proxy|^nmproxy: Protocol byte is not 8\n$',
    b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'mssql|mssql|^\x05\x6e\x00|^\x04\x01|;MSSQLSERVER;',
    b'mysql|mysql|mysql_native_password|^\x19\x00\x00\x00\x0a|^\x2c\x00\x00\x00\x0a|hhost \'|khost \'|mysqladmin|whost \'|^[.*]\x00\x00\x00\n.*?\x00',
    b'mysql-secured|mysql-secured|this MySQL server|MariaDB server|\x00\x00\x00\xffj\x04Host',
    b'db2jds|db2jds|^N\x00',
    b'nagiosd|nagiosd|^Sorry, you .*are not among the allowed hosts',
    b'nessus|nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|oracle-tns-listener|\\(ERROR_STACK=|\\(ADDRESS=',
    b'oracle-dbsnmp|oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|oracle-https|^220- ora',
    b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61|^\x4e\x00\x09',
    b'postgresql|postgres|Invalid packet length|^EFATAL',
    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'rpc|rpc|\x01\x86\xa0|\x03\x9b\x65\x42\x00\x00\x00\x01|^\x80\x00\x00',
    b'rsync|rsync|^@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'snmp|snmp|\x41\x01\x02',
    b'socks|socks|^\x05[\x00-\x08]\x00',
    b'ssl|ssl|^..\x04\0.\0\x02|^\x16\x03\x01..\x02...\x03\x01|^\x16\x03\0..\x02...\x03\0|SSL.*GET_CLIENT_HELLO|^-ERR .*tls_start_servertls|^\x16\x03\0\0J\x02\0\0F\x03\0|^\x16\x03\0..\x02\0\0F\x03\0|^\x15\x03\0\0\x02\x02\.*|^\x16\x03\x01..\x02...\x03\x01|^\x16\x03\0..\x02...\x03\0',
    b'sybase|sybase|^\x04\x01\x00',
    b'telnet|telnet|Telnet|^\xff[\xfa-\xff]|^\r\n%connection closed by remote host!\x00$',
    b'rlogin|rlogin|login: |rlogind: |^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    b'tftp|tftp|^\x00[\x03\x05]\x00',
    b'uucp|uucp|^login: password: ',
    b'vnc|vnc|^RFB',
    b'imap|imap|^\* OK.*?IMAP',
    b'pop|pop|^\+OK.*?',
    b'smtp|smtp|^220.*?SMTP|^554 SMTP',
    b'ssh|ssh|^SSH-|connection refused by remote host.',
    b'rtsp|rtsp|^RTSP/',
    b'sip|sip|^SIP/',
    b'nntp|nntp|^200 NNTP',
    b'webmin|webmin|.*MiniServ|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*|\x83\x00\x00\x01\x8f',
    b'mongodb|mongodb|MongoDB',
    b'Rsync|Rsync|@RSYNCD:',
    b'Squid|Squid|X-Squid-Error',
    b'Vmware|Vmware|VMware',
    b'iscsi|iscsi|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'redis|redis|^-ERR unknown command|^-ERR wrong number of arguments|^-DENIED Redis is running',
    b'memcached|memcached|^ERROR\r\n',
    b'websocket|websocket|Server: WebSocket',
    b'https|https|Instead use the HTTPS scheme to access|HTTPS port|Location: https',
    b'SVN|SVN|^\\( success \\( 2 2 \\( \\) \\( edit-pipeline svndiff1 \\)',
    b'dubbo|dubbo|^Unsupported command',
    b'http|elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
)

# 端口到协议映射
def get_server(port):
    SERVER = {
        'FTP': '21',
        'SSH': '22',
        'Telnet': '23',
        'SMTP': '25',
        'DNS': '53',
        'DHCP': '68',
        'HTTP': '80',
        'TFTP': '69',
        'HTTP-alt': '8080',
        'POP3': '110',
        'POP3-SSL': '995',
        'NetBIOS': '139',
        'IMAP': '143',
        'HTTPS': '443',
        'SNMP': '161',
        'LDAP': '389',
        'SMB': '445',
        'SMTPS': '465',
        'Rexec': '512',
        'Rlogin': '513',
        'Rshell': '514',
        'Rsync': '873',
        'IMAPS': '993',
        'Proxy': '1080',
        'JavaRMI': '1099',
        'Oracle-EMCTL': '1158',
        'Lotus': '1352',
        'MSSQL': '1433',
        'MSSQL-Monitor': '1434',
        'Oracle': '1521',
        'PPTP': '1723',
        'cPanel': '2082',
        'cPanel-SSL': '2083',
        'Oracle-XDB-FTP': '2100',
        'Zookeeper': '2181',
        'DA-admin': '2222',
        'Docker': '2375',
        'Zebra': '2604',
        'Gitea-Web': '3000',
        'Squid-Proxy': '3128',
        'MySQL/MariaDB': '3306',
        'Kangle-admin': '3312',
        'RDP': '3389',
        'SVN': '3690',
        'Rundeck': '4440',
        'GlassFish': '4848',
        'SysBase/DB2': '5000',
        'PostgreSQL': '5432',
        'PcAnywhere': '5632',
        'VNC': '5900',
        'TeamViewer': '5938',
        'CouchDB': '5984',
        'Varnish': '6082',
        'Redis': '6379',
        'Aria2': '6800',
        'Weblogic': '9001',
        'Kloxo-admin': '7778',
        'Zabbix': '8069',
        'RouterOS/Winbox': '8291',
        'BT-Panel': '8888',
        'WebSphere': '9090',
        'Elasticsearch': '9300',
        'Virtualmin/Webmin': '10000',
        'Zabbix-agent': '10050',
        'Zabbix-server': '10051',
        'Memcached': '11211',
        'FileZilla-Manager': '14147',
        'MongoDB': '27017',
        'MongoDB-Web': '28017',
        'SAP-NetWeaver': '50000',
        'Hadoop': '50070',
        'HDFS': '9000',
    }
    for k, v in SERVER.items():
        if v == str(port):
            return f"{k}:{port}"
    return f"Unknown:{port}"

# 默认端口列表（精简版）
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 27017]

# 多样化探测包
PROBE = {
    'http': b'GET / HTTP/1.0\r\n\r\n',
    'ftp': b'USER anonymous\r\n',
    'ssh': b'SSH-2.0-OpenSSH_7.4\r\n',
    'mysql': b'\x00\x00\x00\x0a',
    'default': b'',
}

# 根据端口选择探针
def select_probe(port):
    port = str(port)
    if port in ['80', '443', '8080']:
        return PROBE['http']
    elif port == '21':
        return PROBE['ftp']
    elif port == '22':
        return PROBE['ssh']
    elif port == '3306':
        return PROBE['mysql']
    return PROBE['default']

class ScanPort:
    def __init__(self, ipaddr, ports=None):
        """
        初始化参数，支持自定义端口范围
        """
        self.ipaddr = ipaddr
        self.port = []  # 开放端口列表
        self.out = []   # 扫描结果列表
        self.num = 0    # Portspoof 检测标志
        self.total_ports = len(ports) if ports else len(PORTS)
        self.scanned_ports = 0
        self.progress = 0
        self.ports = ports if ports else PORTS
        self.validate_ip()

    def validate_ip(self):
        """
        验证 IP 或域名格式
        """
        try:
            # 移除协议和路径
            ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
            ipaddr = re.sub(r'/\w+', '', ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(r':\d+', '', ipaddr)
            # 验证 IP 格式
            if re.search(r'\d+\.\d+\.\d+\.\d+', ipaddr):
                ipaddress.ip_address(ipaddr)
                self.ipaddr = ipaddr
            else:
                # 验证域名格式
                if not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', ipaddr):
                    raise ValidationError("无效的域名格式")
                self.ipaddr = ipaddr
        except ValueError as e:
            logger.error(f"IP/域名验证失败：{e}")
            raise ValidationError(f"无效的 IP 或域名：{self.ipaddr}")

    def update_progress(self):
        """
        更新扫描进度
        """
        self.scanned_ports += 1
        self.progress = (self.scanned_ports / self.total_ports) * 100
        logger.info(f"扫描进度：{self.progress:.2f}% ({self.scanned_ports}/{self.total_ports})")

    def socket_scan(self, hosts):
        """
        端口扫描核心代码，支持 IPv6 和速率限制
        """
        ip, port = hosts.split(':')
        sock = None
        try:
            if len(set(self.port)) < 25:
                # 支持 IPv6
                if ':' in ip:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = sock.connect_ex((ip, int(port)))
                if result == 0:
                    self.port.append(port)
                    self.update_progress()
                    # 选择合适的探针
                    probe = select_probe(port)
                    response = b''
                    if probe:
                        sock.sendall(probe)
                        response = sock.recv(256)
                    if response:
                        for pattern in SIGNS:
                            pattern = pattern.split(b'|')
                            try:
                                if re.search(pattern[-1], response, re.IGNORECASE):
                                    proto = f"{pattern[1].decode()}:{port}"
                                    self.out.append(proto)
                                    break
                            except re.error as e:
                                logger.error(f"正则表达式错误在模式 {pattern[-1].decode()}: {e}")
                                continue
            else:
                # 改进 Portspoof 检测
                if len(set(self.out)) < 5:
                    self.num = 1
            time.sleep(0.1)  # 速率限制，每 0.1 秒扫描一个端口
        except socket.timeout:
            logger.debug(f"{ip}:{port} 连接超时")
        except ConnectionResetError:
            logger.debug(f"{ip}:{port} 连接被重置")
        except Exception as e:
            logger.error(f"扫描 {ip}:{port} 时出错：{e}")
        finally:
            if sock:
                sock.close()

    def run(self, ip):
        """
        多线程扫描
        """
        hosts = []
        for i in self.ports:
            hosts.append(f"{ip}:{i}")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADNUM) as executor:
                executor.map(self.socket_scan, hosts)
        except Exception as e:
            logger.error(f"多线程扫描出错：{e}")

    def pool(self):
        """
        扫描入口方法
        """
        out = []
        try:
            if re.search(r'\d+\.\d+\.\d+\.\d+', self.ipaddr):
                ipaddr = self.ipaddr
            else:
                ipaddr = socket.gethostbyname(self.ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(r':\d+', '', ipaddr)
            logger.info(f"开始扫描：{ipaddr}")
            self.run(ipaddr)
        except socket.gaierror:
            logger.error(f"无法解析域名：{self.ipaddr}")
            raise ValidationError(f"无法解析域名：{self.ipaddr}")
        except Exception as e:
            logger.error(f"扫描失败：{e}")
            raise ValidationError(f"扫描失败：{e}")
        for i in self.out:
            _, port = i.split(':')
            out.append(port)
        for i in self.port:
            if i not in out:
                self.out.append(get_server(i))
        if self.num == 1:
            return ['Portspoof:0']
        return list(set(self.out))

    for pattern in SIGNS:
        try:
            re.compile(pattern.split(b'|')[-1])
        except re.error as e:
            logger.error(f"无效正则表达式 {pattern.decode()}: {e}")

if __name__ == "__main__":
    try:
        scanner = ScanPort('45.33.32.156', ports=[22, 80, 443])
        print(scanner.pool())
    except ValidationError as e:
        print(f"错误：{e}")




