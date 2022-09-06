# -*- coding:utf8 -*-
#__author__ = Angleashuaiby
import dpkt
import socket
import json
import re
import time
import subprocess
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

monitorTime = 120	#设置监听间隔时间，即每个包的时间段，建议60-180
maxAccess = 50	#在监听时间内，允许同一个IP访问同一个接口的最大次数，与间隔时间结合配置
expWhite = ["js","css","png","ico"]		#后缀名白名单，在此白名单中不会抓包分析
netInterface = "en0"	#监听的网络接口，务必自行更改设置

def sendMessage(message):
	formdata = {"msgtype": "markdown","markdown": {"title":"警告,发现疑似红队重放攻击。","text":message}}
	headers = {'content-type': 'application/json'}
	url = "https://oapi.dingtalk.com/robot/send?access_token=000000000000000000000"	#钉钉机器人token自行替换
	resp = requests.post(url,data=json.dumps(formdata),headers=headers,verify=False)

def findAttack(pcap):
	sourIpCount = {}
	for (ts, buf) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf) #解包，物理层
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			dport =ip.data.dport
			if dport == 80:
				content =ip.data.data
				if content:
					urlApi =re.findall(r"[ES]T ([\S]*) HTTP/1.[012]",str(content))[0]
					if "/?" in urlApi:	#GET传参
						urlApi = urlApi.split("/?",1)[0]
					try:
						ext = urlApi.rsplit(".",1)[1]
					except:
						ext = ''
					if ext not in expWhite:	#过滤掉白名单后缀文件
							session = src + '-' + dst + '-' + urlApi
							if session in sourIpCount.keys():
								sourIpCount[session] += 1
							else:
								sourIpCount[session] = 1
		except:
			pass
	for sess in sourIpCount:
		if sourIpCount[sess] > maxAccess:
			src = sess.split('-')[0]
			dst = sess.split('-')[1]
			urlApi = sess.split('-')[2]
			result = '[+] 警告,发现疑似红队重放攻击：源IP：%s |目的IP：%s |攻击url接口为%s, |攻击次数为%s，攻击时间为：%s'%(src,dst,urlApi,str(sourIpCount[sess]),time.strftime("%Y_%m_%d_%H:%M"))
			print(result)
			sendMessage(result)

def main():
	while True:
		print("[-] 流量监听中，当前时间为: "+time.strftime("%Y_%m_%d_%H:%M:%S"))
		fileName = time.strftime("%Y_%m_%d_%H:%M:%S.pcap")
		#tcpdump获取数据包
		p = subprocess.Popen(["exec tcpdump -i %s -w %s"%(netInterface,fileName)],shell=True)	#流量过大时，建议指定端口或者协议。
		time.sleep(monitorTime)	#持续监听
		p.terminate()
		p.wait()	#再次调用wait()以防出现bug。
		f = open(fileName, mode='rb')
		try:
			pcap = dpkt.pcap.Reader(f)
		except:
			pcap = dpkt.pcapng.Reader(f)
		findAttack(pcap)
		f.close()
		print("\r\n--------------------\r\n")

if __name__ == '__main__':
	main()