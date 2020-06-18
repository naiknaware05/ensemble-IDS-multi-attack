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
#Creating lists of different attack so that types can be identified.
dos=['back','land','neptune','pod','smurf','teardrop','apache2','udpstorm','processtable','worm']
probe=['satan','ipsweep','nmap','portsweep','mscan','saint']
r2l=['guess_password','ftp_write','imap','phf','multihop','warezmaster','warezclient','spy','xlock','xsnoop','snmpguess','snmpgetattack','httptunnel','sendmail','named']
u2r=['buffer_overflow','loadmodule','rootkit','perl','sqlattack','xterm','ps']
import numpy as np
import pandas as pd
import tkinter
from tkinter import *
import pickle
#classifier's pickle file
with open('random_forest_classifier.pkl', 'rb') as file:  
    eclf3 = pickle.load(file)
#from pandas.stats.api import ols
LARGE_FONT= ('Arial 15  bold')
NORM_FONT= ('Helvetica 10 bold')
SMALL_FONT= ('Helvetica 8 bold')


#Code for history button
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
	font= ('Arial', 12),borderwidth=1.5, relief="flat")
	B3.pack(side = "bottom",pady=10 )
	
	
	


#Code for find button
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
		if s[x][-1]!='normal':
			
			if s[x][-1] in dos:
				e='dos' 
			elif s[x][-1] in probe:
				e='probe'
			elif s[x][-1] in r2l:
				e='r2l'
			elif s[x][-1] in u2r:
				e='u2r'
			
			t.insert(END,'  '+s[x][1]+ '              '+ s[x][-1]+'            '+e+'\n' )
			t.tag_add("center", "0.0", "end")
			t.pack(padx=20,pady=20)
	
	B4 = Button(window, text="History", command=lambda:[window.destroy(),log(d1)] , width=5, height=1 , fg='white', bg='IndianRed3', 
	font= ('Arial', 12),borderwidth=1.5, relief="flat")
	B4.pack(side = "left",padx=70,pady=15 )

	
	
	B3 = Button(window, text="Cancel", command = window.destroy , width=4, height=1 , fg='white', bg='IndianRed3', 
	font= ('Arial', 12),borderwidth=1.5, relief="flat")
	B3.pack(side = "right",padx=70,pady=15 )


	
	

#Code for popup function
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
	
	

#prediction function
def worker2(m,k):  
	KDD_Extractor_features_26 = ['duration', 'src_bytes', 'dst_bytes', 'land', 
                             'wrong_fragment', 'urgent', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
                             'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                             'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                             'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                             'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
                             #features on which model trained

	#preparing dataset
	from sklearn.preprocessing import LabelEncoder
	dataset1=pd.read_csv("/home/aniket/intermediate_log.csv")
	dataset1.dropna(how='any',axis=0,inplace = True)
	X1= pd.DataFrame(data = dataset1.iloc[m:k], columns = KDD_Extractor_features_26)
	a=[]
	a = pd.Series([]) 
	temp=X1.shape
	try:
		if temp==0:
			raise ValueError("No packets captured")

		a=eclf3.predict(X1)	#predicting function
		


		d=[[]]
		

		with open('intermediate_log.csv', newline='') as f:
			reader = csv.reader(f)
			ir=[row for idx, row in enumerate(reader) if idx in range(m+1,k+1)]
			d=list(ir)
		
		for i in range(0,len(d)):
			d[i].append(a[i])
			
		count=0
		for i in range(0,len(d)):
			if d[i][-1]!='normal':
				count=count+1

		datasetlog=pd.read_csv("/home/aniket/final_log.csv")
		dataset1=pd.read_csv("/home/aniket/intermediate_log.csv").iloc[m:k]
		
		dataset1.insert(33,'label',a)
		#section for filling label column		
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

		#inserting type of attack 		
		if count>1:
			dataset1.insert(35, "Single/Multi",'Multiattack')
		elif count == 1:
			dataset1.insert(35, "Single/Multi",'Single')	
		
		#appending predicted data to final_log.csv		
		result=pd.concat([datasetlog,dataset1])
		result.to_csv("final_log.csv",index=False)
		
		
		with open('final_log.csv', newline='') as f:
			reader = csv.reader(f)
			for row in reader:
				d1 = list(reader)#input for popup if attack

		
		if count>1:
			popupmsg(d,d1,count)	#calling popup function
	except ValueError as ve:
		ve=ve

import multiprocessing 
import os 


if __name__ == "__main__": 
	
	worker2(int(str(sys.argv[1])),int(str(sys.argv[2])))
