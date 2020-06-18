#code for connecting gui with pcap_to_csv
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

def main(arg):
	t_end=time.time()+15	#to set the time to stop prediction since new set of packets are to be captured here after every 20sec so time set to 15 sec
	k=int(str(arg))		#packets predicted till now
	data = pd.read_csv("intermediate_log.csv", header=0)
	col_a = list(data.timestamp)	#timestamp values from intermediate_log.csv
	i=0	
	while time.time() < t_end and len(col_a)>k:
		m=k
		k=col_a[::-1].index(col_a[m])
		cu=col_a[m:k]	#values to be predicted by gui from intermediate_log.csv
		strg="(sudo python3 gui.py "+str(m)+" "+str(k)+")"
		subprocess.call(strg,shell=True)	#calling gui.py
		#uncomment this part to get csv file for predicted packets in every 1 second
		'''with open('returns'+str(i)+'.csv', 'w') as f:
			writer = csv.writer(f)
			for val in cu:
				writer.writerow([val])'''
		i+=1
		
	print(k)	#sending back new number of packets predicted to pcap_to_csv

if __name__ == "__main__":
	main(sys.argv[-1])	#argument from pcap_to_csv i.e. packets predicted till now
