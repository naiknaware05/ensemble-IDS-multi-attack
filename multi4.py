import sys
import multiprocessing 
import os 
import subprocess
import pandas as pd
from scapy.all import sniff
from scapy.all import wrpcap
import time
import csv
import tkinter as tk
from tkinter import ttk
dos=['back','land','neptune','pod','smurf','teardrop','apache2','udpstorm','processtable','worm']
probe=['satan','ipsweep','nmap','portsweep','mscan','saint']
r2l=['guess_password','ftp_write','imap','phf','multihop','warezmaster','warezclient','spy','xlock','xsnoop','snmpguess','snmpgetattack','httptunnel','sendmail','named']
u2r=['buffer_overflow','loadmodule','rootkit','perl','sqlattack','xterm','ps']
import numpy as np
import pandas as pd
import tkinter
from tkinter import *
import pickle
with open('tpmodel.pkl', 'rb') as file:  
    eclf3 = pickle.load(file)
#from pandas.stats.api import ols
LARGE_FONT= ('Arial 15  bold')
NORM_FONT= ('Helvetica 10 bold')
SMALL_FONT= ('Helvetica 8 bold')

def log(d1):
	window1 = Toplevel()
	window1.configure(background='white')
	window1.minsize(500,200)
	window1.wm_title("Attacks History")
	t= Text(window1)
	t.tag_configure("center", justify='center')
	t.configure(background='black',fg='white')
	t.insert(END,'\n')
	t.insert(END,'Attacks Being Conducted:')
	t.insert(END,'\n''\n')
	t.insert(END,'Protocol    Flag    Label    Class    Single/Multi    Timestamp''\n' )
	for x in range(0,len(d1)): 
		t.insert(END,'  '+d1[x][1]+'   '+d1[x][3]+'   '+d1[x][33]+'   '+d1[x][34]+'   '+d1[x][35]+'   '+d1[x][32]+'\n')
		t.tag_add("center", "0.0", "end")
		t.pack(padx=20,pady=20)
	
	B3 = Button(window1, text="Cancel", command = window1.destroy , width=7, height=1 , fg='white', bg='IndianRed3', 
	font= ('Arial', 12),borderwidth=1.5, relief="flat")#.grid(row=2, column=5)
	B3.pack(side = "bottom",pady=10 )
	#f.close()
	
	



def find(s,d1,count):
	window = Toplevel()
	window.configure(background='black')
	window.minsize(700,200)
	window.wm_title("Attack_Info")
	t= Text(window)
	t.tag_configure("center", justify='center')
	t.configure(background='black',fg='white')
	t.insert(END, '\n')
	t.insert(END,'Number of Multiattacks:  ')
	t.insert(END, count)
	t.insert(END,'\n''\n')
	t.insert(END,'Type of Attacks:''\n')
	t.insert(END,'\n')
	t.insert(END,'Protocol            Label             Class''\n' )
	for x in range(0,len(s)):
		if s[x][-1]!='Normal':
			e='normal'
			if s[x][-1] in dos:
				e='dos' 
			elif s[x][-1] in probe:
				e='probe'
			elif s[x][-1] in r2l:
				e='r2l'
			elif s[x][-1] in u2r:
				e='u2r'
			#else e='normal'
				#e='normal'
			t.insert(END,'  '+s[x][1]+ '              '+ s[x][-1]+'            '+e+'\n' )
			t.tag_add("center", "0.0", "end")
			t.pack(padx=20,pady=20)
	
	B4 = Button(window, text="History", command=lambda:[window.destroy(),log(d1)] , width=5, height=1 , fg='white', bg='IndianRed3', 
	font= ('Arial', 12),borderwidth=1.5, relief="flat")#.grid(row=2, column=5)
	B4.pack(side = "left",padx=70,pady=15 )

	
	
	B3 = Button(window, text="Cancel", command = window.destroy , width=4, height=1 , fg='white', bg='IndianRed3', 
	font= ('Arial', 12),borderwidth=1.5, relief="flat")#.grid(row=2, column=5)
	B3.pack(side = "right",padx=70,pady=15 )


	
	


def popupmsg(s,d1,count):
	popup = Tk()
	popup.configure(background='snow')
	popup.minsize(250, 100) 
	popup.wm_title("ALERT!")
	Label1 = Label(popup, text='Multiattack Detected!!!!', bg = "snow",fg = "black",font = LARGE_FONT) 
	Label1.pack(side="top",fill='x',padx=10,pady=10)
	
	B1 = Button(popup, text="Cancel", command = popup.destroy , width=4, height=1 , fg='white', bg='IndianRed3', 			font= ('Arial', 12),borderwidth=1.5, relief="flat")
	B1.pack(side = "right",padx=12)
	
	B2 = Button(popup, text="Find",command = lambda:find(s,d1,count) , width=4, height=1,fg='white', bg='IndianRed3', 		font=('Arial',12),borderwidth=1.5,relief="flat")
	B2.pack(side= "left", padx=12)
	
	popup.after(15000, popup.destroy)
	popup.mainloop()
	
	
	

def worker1(i): #pcap file function
	pkt_list=sniff(timeout=20)
	print(pkt_list)
	filename="checktcp"+str(i)+".pcap"
	wrpcap(filename,pkt_list)

def worker2(m,k):  #pcap to csv function
	KDD_Extractor_features_26 = ['duration', 'src_bytes', 'dst_bytes', 'land', 
                             'wrong_fragment', 'urgent', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
                             'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                             'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                             'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                             'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

	from sklearn.preprocessing import LabelEncoder
	dataset1=pd.read_csv("/home/aniket/log.csv")
	
	
#print("Testing Dataset : ",y1.shape)
 
#Drop tuples with null values 
# X1 and y1 contains all 42 column
	dataset1.dropna(how='any',axis=0,inplace = True)
	#dataset1.isnull().sum().sum()
	#dataset1.dropna()
	X1= pd.DataFrame(data = dataset1.iloc[m:k], columns = KDD_Extractor_features_26)
	#print((m, k))
	#X1=dataset1.iloc[m:k,:28]#except last read all
	#print(X1)
	#X1=X1.apply(LabelEncoder().fit_transform)
	#print(X1)
	#print(eclf3.predict(X1))
	a=[]
	a = pd.Series([]) 
	#print("Any null values in Testing dataset : ", X1.isnull().values.any())
	#X1.to_csv('x1.csv',index=False)
	a=eclf3.predict(X1)
	


	d=[[]]
	
	#print(a[1])
	with open('log.csv', newline='') as f:
		reader = csv.reader(f)
		ir=[row for idx, row in enumerate(reader) if idx in range(m+1,k+1)]
		d=list(ir)
	
	for i in range(0,len(d)):
		d[i].append(a[i])
		
	count=0
	for i in range(0,len(d)):
		if d[i][-1]!='Normal':
			count=count+1

	datasetlog=pd.read_csv("/home/aniket/olog.csv")
	dataset1=pd.read_csv("/home/aniket/log.csv").iloc[m:k]
	
	dataset1.insert(33,'label',a)
	val = pd.Series([]) 
	for x in range(len(a)):
		if dataset1["label"].iloc[x] in dos:
			val[x]='dos' 
		elif dataset1["label"].iloc[x] in probe:
			val[x]='probe'
		elif dataset1["label"].iloc[x] in r2l:
			val[x]='r2l'
		elif dataset1["label"].iloc[x] in u2r:
			val[x]='u2r'
		elif dataset1["label"].iloc[x] == "normal":
			val[x]='normal'	
	dataset1.insert(34, "Class", val)		
	if count>1:
		dataset1.insert(35, "Single/Multi",'Multiattack')
	elif count == 1:
		dataset1.insert(35, "Single/Multi",'Single')	
			
	result=pd.concat([datasetlog,dataset1])
	result.to_csv("olog.csv",index=False)
	
	
	with open('olog.csv', newline='') as f:
		reader = csv.reader(f)
		for row in reader:
			d1 = list(reader)

	
	
	popupmsg(d,d1,count)
	

import multiprocessing 
import os 


if __name__ == "__main__": 
	
	worker2(int(str(sys.argv[1])),int(str(sys.argv[2])))
