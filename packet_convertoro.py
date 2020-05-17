import sys
import multiprocessing 
import os 
import subprocess
import pandas as pd
from scapy.all import sniff
from scapy.all import wrpcap
import time
import datetime
import csv

hel=0

def worker1(i): #pcap file function
	
	pkt_list=sniff(timeout=20)
	print(pkt_list)
	filename="checktcp"+str(i)+".pcap"
	wrpcap(filename,pkt_list)


def worker2(i,t_end):  #pcap to csv function
	
	filename="attacks"+str(i)+".csv"
	pcap_filename="checktcp"+str(i)+".pcap"
	
	with open(filename,'w',newline='') as f:
		w = csv.writer(f)
		w.writerow(cols)

	stri="(sudo ./kdd99extractor -e "+pcap_filename+" >> "+filename+")"
	strl="(sudo ./kdd99extractor -e "+pcap_filename+" >> log.csv)"
	
	df=pd.read_csv("log.csv")
	df.sort_values(by='timestamp', ascending=True, inplace =True)
	#print(df)
	df.to_csv("log.csv",index=False)
	tmp=subprocess.call(stri,shell=True)
	subprocess.call(strl,shell=True)
	global hel	
	print(hel)
	#strlog="(sudo python3 packetlog.py "+str(global hel)+")"
	strlog=["sudo","python3","packetlog.py",str(hel)]
	f=subprocess.check_output(strlog)
	hel=int(f.decode('utf-8'))
	print("output"+str(hel))
	print("NOOOOO")
	df1=pd.read_csv("/home/aniket/log.csv").iloc[:hel,:]
	df2=pd.read_csv("/home/aniket/templog.csv")
	result=pd.concat([df2,df1])
	result.to_csv("templog.csv",index=False)
	df1=pd.read_csv("/home/aniket/log.csv").iloc[hel:,:]
	df1.to_csv("log.csv",index=False)
	
def worker3(i):
	p3 = multiprocessing.Process(target=worker1, args=(i, )) 
	p4 = multiprocessing.Process(target=worker2, args=((i-1), )) 
	p4.start() 
	p3.start() 
	p3.join() 
	p4.join()

def worker4(t_end):
	data = pd.read_csv("log.csv", header=0)
	col_a = list(data.timestamp)
	#print(col_a)
	print("worker4 "+str(worker4.k))
	while time.time() < t_end and len(col_a)>worker4.k:
		m=worker4.k
		print("m "+str(m))
		print('col_a.count(col_a[worker4.k])'+str(col_a.count(col_a[worker4.k]))+col_a[worker4.k])
		worker4.k=m+col_a.count(col_a[worker4.k])
		print("helloooooooooooooooooooooooooooooooooooo")
		
	print("welcomeoooooooooooooooooooooooooooooooooooo")
	
	



# importing the multiprocessing %ule 
import multiprocessing 
import os 


if __name__ == "__main__": 
	# printing main program process id
	cols = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","source_ip","s_portno","destinaton_ip","d_portno","timestamp",'label',"Class",'Single/Multi']
	
	with open("olog.csv",'w',newline='') as f:
		w1 = csv.writer(f)
		w1.writerow(cols)
	cols = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","source_ip","s_portno","destinaton_ip","d_portno","timestamp"]
	with open("log.csv",'w',newline='') as f:
		w1 = csv.writer(f)
		w1.writerow(cols)
	with open("templog.csv",'w',newline='') as f:
		w1 = csv.writer(f)
		w1.writerow(cols)
	
	#strl="(sudo ./kdd99extractor -e "+pcap_filename+" >> log.csv)" 
	print("ID of main process: {}".format(os.getpid())) 

	#ftr = [3600,60,1]
	#ti=sum([a*b for a,b in zip(ftr, [int(i) for i in timestr.split(":")])])
	#x = time.strptime('2020-04-02T00:40:56'.split('T')[1],'%H:%M:%S')
	#print(datetime.timedelta(hours=x.tm_hour,minutes=x.tm_min,seconds=x.tm_sec).total_seconds())
	i=1
	k=0
	from datetime import datetime # Current date time in local system 
	print(str(datetime.now()))
	# timer started
	#t_start=time.time()
	print(time.time())
	t_end = time.time() + 60 * 1
	o=subprocess.call("cd /sys/class/net/ | grep "" eth0/operstate",shell=True)
	#subprocess.call("(va=$(grep "" eth0/operstate)",shell=True)
	#print(o)
	if o==1:
		pkt_list0=sniff(timeout=20)
		print(pkt_list0)

		wrpcap('checktcp0.pcap',pkt_list0)
		
		while time.time()<t_end:
		#while time.time() < t_end:
			p1 = multiprocessing.Process(target=worker1, args=(i, )) 
			p2 = multiprocessing.Process(target=worker2, args=((i-1),(time.time()+15), )) 
			p2.start()
			p1.start() 
			p1.join() 
			p2.join()
			print("k"+str(hel))
			i+=1
		worker2(i-1,0)
		t_end=time.time()+300
		print("mayo")
		'''while time.time()<t_end:
			worker2(i-1,0)'''
	print(hel)
	
	
