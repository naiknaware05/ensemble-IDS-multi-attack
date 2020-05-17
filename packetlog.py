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
#print(str(sys.argv[-1]))
def main(arg):
	t_end=time.time()+15
	k=int(str(arg))
	#print(str(k))
	data = pd.read_csv("log.csv", header=0)
	col_a = list(data.timestamp)
	i=0	
	while time.time() < t_end and len(col_a)>k:
		m=k
		cu=col_a[m:k]
		#hhhh=
		strg="(sudo python3 multi4.py "+str(m)+" "+str(k)+")"
		subprocess.call(strg,shell=True)
		with open('returns'+str(i)+'.csv', 'w') as f:
			writer = csv.writer(f)
			for val in cu:
				writer.writerow([val])
		i+=1
		
	#print("welcomeoooooooooooooooooooooooooooooooooooo")
	print(k)
if __name__ == "__main__":
	main(sys.argv[-1])
