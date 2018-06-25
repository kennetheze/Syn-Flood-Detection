#!/usr/bin/python

#To run: python3 SynDetector.py
#must be run with root permissions.


from time import gmtime, strftime
import threading
import subprocess
import os,logging,netifaces
import multiprocessing
from struct import *
from datetime import date,datetime
import logging
import sys,os
import getopt
import sh
import socket
import struct
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk
from io import StringIO

APP_DIR = os.path.abspath(os.path.dirname(sys.executable))


#++++++++ Global variable ++++++++++++ 


maxIPsSPkts_min = 10 #max Hosts to send SYN Pkts/min
maxS_IPmin = 10 #max SYN pkts per IP/min

interF=None

TCPDetectionsList=["<<<<>>>>  TCP-SYN Attack  <<<<>>>>\n\n"]
TCPDetectedTupple=("",)

#++++++++ Parent Window and main Logic +++++++++	

class Application():
	
	def __init__(self):
		self.if_list = netifaces.interfaces() #find all the interfaces.
	
		'''  Building main window '''
		#1: Create a builder
		self.builder = b = Gtk.Builder()
		#2: Load ui file
		fpath = os.path.join(os.path.dirname(__file__),"Tool.glade")
		b.add_from_file(fpath)

		#Get the GUI components.All the ids ending with _1 belong to ARP GUI form
		self.mainwindow = b.get_object('mainWindow')
		self.OText = b.get_object('textbuffer_progress')
		self.OText_1 = b.get_object('textbuffer_progress')
		self.SText = b.get_object('textbuffer_screen')
		self.Stext_1 = b.get_object('textbuffer_screen')
		self.filechooser = b.get_object('pcapFileChooser')
		handlers = {
		'viewTCPDetections':self.viewTCPDetections,
		'StartTCPSyn':self.StartTCPSyn,
		'StopTCPSyn':self.StopTCPSyn,
		'viewPcap':self.openDump,
		'system_exit':self.systemExit,
		}

		b.connect_signals(handlers)

		screen = Gdk.Screen.get_default()
		css_provider = Gtk.CssProvider()
		css_provider.load_from_path('colors.css')
		context = Gtk.StyleContext()
		context.add_provider_for_screen(screen, css_provider,Gtk.STYLE_PROVIDER_PRIORITY_USER)
		self.mainwindow.show_all()



		''' building settings dialog '''
		self.builder_1 = d = Gtk.Builder()
		fpath_dialog = os.path.join(os.path.dirname(__file__),"settings.glade")
		d.add_from_file(fpath_dialog)

		self.settingsDialog = d.get_object('dialogwindow')
		self.Net_Iface = d.get_object('Net_Interface')
		self.SaveToPcap_E = d.get_object('SaveToPcap')
		self.option_1 = d.get_object('syn_count_min')
		self.option_2 = d.get_object('syn_ip_min')
		self.messagebox = d.get_object('alert_box')

		handlers_1 = {
		'proceed':self.proceed,
		'ok':self.ok,
		'system_exit_setting':self.exitSetting,		
		}
		d.connect_signals(handlers_1)

		screen_1 = Gdk.Screen.get_default()
		css_provider_1 = Gtk.CssProvider()
		css_provider_1.load_from_path('SettingDesign.css')
		context_1 = Gtk.StyleContext()
		context_1.add_provider_for_screen(screen_1, css_provider_1,Gtk.STYLE_PROVIDER_PRIORITY_USER)
		self.settingsDialog.show_all()

		for _if in self.if_list:
			self.Net_Iface.append_text(_if)
		''' end of building dialog '''

		
		self.tm = threading.Thread(name='unresCountReseter', target=self.unresCountReseterTimer)
		self.tm.setDaemon(True)
		self.TcpSynAtt = threading.Thread(name='TCPSYN_Flood_Detection', target=self.TCPSYN_Detection)
		self.TcpSynAtt.setDaemon(True)
		self.unresTuple=("",)
		self.MaxSAttackTuple=("",)
		self.dump_file = "Detections.pcap"
		self.DetectionsFile = "Detections.txt"
		self.click=1
		self.click_stop=1
		self.unresCount=1
		self.HostCount=0

	
	def proceed(self,master):
		global maxS_IPmin, maxIPsSPkts_min, interF
		
		if self.option_1.get_value_as_int() != 0:
			maxS_IPmin = self.option_1.get_value_as_int()
		if self.option_2.get_value_as_int() != 0:
			maxIPsSPkts_min = self.option_2.get_value_as_int()

		interF = self.Net_Iface.get_active_text()
		
		if interF != None:
			self.settingsDialog.hide()
		else:	
			self.messagebox.run()

	def ok(self,master):
		self.messagebox.hide()

	'''+++++++ display TCP Detection +++++++'''
	def viewTCPDetections(self,master):

		for A in  range(0,len(TCPDetectionsList)):
			B=TCPDetectionsList[A]+"\n"	
			start_iter = self.SText.get_start_iter()
			end_iter = self.SText.get_end_iter()
			self.SText.delete(start_iter,end_iter)
			self.SText.insert(start_iter,B)
	
	''' +++++++ Starting the Threading +++++++'''
	def TCPSYNFloodDetection(self):
		try:
			self.TcpSynAtt.start()
		except:
			self.TcpSynAtt._is_running = False
		

	#------------- Get local IP ------------	
	def getNetParams(self):
		#gets the interface for detection
		
		try:
			addrs = netifaces.ifaddresses(interF)
		except:
			self._is_running = False
		try:
			#Get the ip address 
			local_ip = addrs[netifaces.AF_INET][0]["addr"]
			self.broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
		except KeyError:
			exit("Could not read address ".format(InterF))
		return local_ip

	
		

	#-------Starting and Ending Detections------	
	def StartTCPSyn(self,master):
		if self.click == 1:
			#Flush all firewall rules
			os.system("iptables -F")
			self.TCPSYNFloodDetection()
			self.unresCountReseter_Min()
			end_iter = self.OText.get_start_iter()
			self.OText.insert(end_iter,"\n>>TCP detection started!")
			self.click+=1
		elif self.click == 2:
			self.click += 1
			end_iter = self.OText.get_start_iter()
			self.OText.insert(end_iter,"\n>>Cannot start again, Restarting Tool Again.")
		
	
		
	def StopTCPSyn(self,master):
		if self.click_stop == 1 and self.click == 2:
			self.TcpSynAtt._is_running = False
			self.tm._is_running = False
			os.system("iptables -F")	#Flush all firewall rules
			end_iter = self.OText.get_start_iter()
			self.OText.insert(end_iter,"\n>>TCP detection stopped!")
			self.click_stop+=1
		elif self.click_stop == 2:
			end_iter = self.OText.get_start_iter()
			self.OText.insert(end_iter,"\n>>Already stopped!")
			self.click_stop+=1



		
	def TCPSYN_Detection(self):
		''' +++++++ TCP-SYN Attack Detection +++++++'''
		
		#Flush firewall rules to start afresh
		os.system("iptables -F")  
		#sniff and call to syn_Attack(self) to process the sniffed packets
		pkt=sniff(iface=interF,filter='tcp[0xd]&18=2', prn=self.syn_Attack)
		
	#------------------Call to process sniffed syn packets------------------
	def syn_Attack(self, pkt):
		''' Tcp Syn Attack Prevention: block hosts reaching maximum connections '''
		global TCPDetectedTupple
		host=pkt[0][1].src
		localIp = self.getNetParams() 
		WritePcap=self.SaveToPcap_E.get_active()
		if(localIp != host):
			if (host in self.unresTuple) and (not host in TCPDetectedTupple):
				if(self.unresCount > maxS_IPmin-1):#Drop SYN Requests on reaching Maximum attempts per IP 
					#block host reaching maximum SYN attempts per IP
					if host not in self.MaxSAttackTuple:
						if(self.unresCount == maxS_IPmin-1):
							#block host coming after reaching maximum SYN attempts per IP
							os.system('iptables -A INPUT -p tcp -s '+str(host)+' -j DROP')
						else:
							
							self.WriteOut("TCP-SYN", host)
							os.system('iptables -A INPUT -p tcp -s '+str(host)+' -j DROP')
							end_iter = self.OText.get_start_iter()
							self.OText.insert(end_iter,"\n>>TCP-SYN Attack Detected")
							if(WritePcap):
								wrpcap(self.dump_file, pkt, append=True, sync=True)
							self.MaxSAttackTuple+=(host,)
							#Reset the count to avoid another genuine host being detected as an attacker 
							self.unresCount=1
							TCPDetectedTupple+=(host,)
					else:
						pass
				else:
					self.unresCount+=1
			else:
				self.unresTuple+=(host,)
				self.HostCount+=1
				if(self.HostCount > maxIPsSPkts_min) and (not host in TCPDetectedTupple):#Drop SYN Requests on reaching Maximum set Hosts/IPs to send syn				
						os.system('iptables -A INPUT -p tcp -s '+str(host)+' -j DROP')
						end_iter = self.OText.get_start_iter()
						self.OText.insert(end_iter,"\n>>TCP Connection Droped -reached maximum Host Count")
						self.WriteOut("TCP-SYN", host)
						if(str(WritePcap) =="Yes"):
							wrpcap(self.dump_file, pkt, append=True, sync=True)
						TCPDetectedTupple+=(host,)
							
					
				
		else:
			pass
	#--- Reseting the SYN counter 
	def unresCountReseter_Min(self):
		self.tm.start()
		
	def unresCountReseterTimer(self):
		while True:
			time.sleep(60)
			self.unresCount=1

		''' +++++++ for open pcap file +++++++ '''
	def openDump(self, master):
		dpath = self.filechooser.get_filename()
		B = [dpath]
		packets = rdpcap(dpath)
		''' redirecting standard output to a string variable  '''
		capture = StringIO()
		save_stdout = sys.stdout
		sys.stdout = capture
		packets.show()
		sys.stdout = save_stdout
		
		start_iter = self.SText.get_start_iter()
		end_iter = self.SText.get_end_iter()
		self.SText.delete(start_iter,end_iter)
		self.SText.insert(start_iter,capture.getvalue())	

	#------- Write Detections To txt file and keep IP's in memory -----------
	def WriteOut(self, attack, source):
		'''write out detection'''
		global TCPDetectionsList
		#dt=strftime("%Y-%m-%d %H:%M:%S", gmtime())
		data="\n|"+attack+"|:  "+time.ctime()+" Hours [ "+source+" ]"
		data1=source+"    "+time.ctime()+" Hours"
		out_txt = open(self.DetectionsFile,'a')
		out_txt.writelines(data)
		out_txt.close()
		if(attack=="TCP-SYN"):
			TCPDetectionsList.append(data1)


	def systemExit(self,master):
		os.system("iptables -F")
		sys.exit()
	
	def exitSetting(self,master):
		sys.exit()
				   

if __name__ == "__main__": 
	main = Application()
	Gtk.main()
