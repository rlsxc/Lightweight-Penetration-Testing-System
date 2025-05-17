import socket
import threading
'''
子域名搜素模块
环境配置：
1.采用字典TOP 10000 的域名，中的sub_domain.txt
字典下载网址：https://gitee.com/halftion/oh-my-free-data
2.使用该模块需要配置一下sub_domain_filename变量，此为字典的位置
'''
sub_domain_filename=r'D:\Cyber_security_tools\字典\sub_domain\dnspod-tlds.txt'
#读取子域名文件
def readSubDomainList():
    subDomainList = []
    try:
        file = open(sub_domain_filename, 'r')
        for line in file:
            subDomainList.append(line[:-1])
            # 这里切片的作用是去掉换行
        file.close()
    except Exception as e:
        pass
    return subDomainList
#拼接域名
def splitSubDomain(domain,subDomainList):
    subDomains = []
    for item in subDomainList:
        subDomains.append(item + '.' + domain)
    return subDomains
def domainToip(domain):
    iplist = []
    try:
        results = socket.getaddrinfo(domain , None)
        for item in results:
            # item实际蕴含域名的whois信息，这里只取用返回的ip记录
            iplist.append(item[4][0])
    except Exception as e:
        pass
    return iplist


# 结果列表：
resultList = []
class DomainMinner(threading.Thread):
    def __init__(self, domain):
        threading.Thread.__init__(self)
        self.domain = domain
    def run(self):
        iplist = domainToip(self.domain)
        subDomain = {}
        if len(iplist) > 0:
            subDomain['domain'] = self.domain
            subDomain['iplist'] = iplist
            # 判断是否可能存在CDN
            subDomain['isCDN'] = False
            if len(iplist) > 1:
                subDomain['isCDN'] = True
            resultList.append(subDomain)


# 线程锁和临界资源：
threadLock = threading.Lock()
resultList = []


class DomainMinner(threading.Thread):
    def __init__(self, domain):
        threading.Thread.__init__(self)
        self.domain = domain

    def run(self):
        iplist = domainToip(self.domain)
        subDomain = {}
        if len(iplist) > 0:
            subDomain['domain'] = self.domain
            subDomain['iplist'] = iplist
            # 判断是否可能存在CDN
            subDomain['isCDN'] = False
            if len(iplist) > 1:
                subDomain['isCDN'] = True
            # 临界区：
            threadLock.acquire()
            resultList.append(subDomain)
            threadLock.release()
def subDominMining(domain):
    threads = []
    subDomainList = readSubDomainList()
    subDomains = splitSubDomain(domain,subDomainList)
    try:
        for item in subDomains:
            thread = DomainMinner(item)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
    except Exception as e:
        pass
    accessible = resultList
    return accessible
# # 子域名扫描，传入根域名信息
# accessible = subDominMining('ctf.show')

