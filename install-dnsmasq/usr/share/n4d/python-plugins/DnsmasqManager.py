# npackage example  https://svn.lliurex.net/pandora/n4d-ldap/trunk
# jinja2 http://jinja.pocoo.org/docs/templates

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader
from jinja2 import Template
import tempfile
import shutil
import os
import subprocess
import re
import tarfile
import imp
import n4d.responses
import n4d.server.core as n4dCore
from n4d.utils import n4d_mv, get_backup_name

dhcpranges=imp.load_source("DhcpRanges","/usr/share/n4d/python-plugins/support/DhcpRanges.py")

MKDIR_ERROR=-10
OPEN_TAR_ERROR=-20
FILE_NOT_FOUND_ERROR=-30
RESTORE_UKNOWN_ERROR=-40
INTERNAL_DOMAIN_UNDEFINED_ERROR=-50
CONFIGURE_INTERNAL_DOMAIN_ERROR=-60
CONFIGURE_LOAD_EXPORTS_ERROR=-70
HOSTNAME_VAR_ERROR=-80
INTERNAL_DOMAIN_VAR_ERROR=-90
SRV_ALIAS_ERROR=-100
ALIAS_ERROR=-110
UNDEFINED_VAR_ERROR=-120
SET_INTERNAL_DNS_ERROR=-130
SET_EXTERNAL_DNS_ERROR=-140
SERVER_LOCKED_ERROR=-150
UNREGISTERED_MAC_ERROR=-160
UNKNOWN_IP_ERROR=-170
NO_DHCP_INFO_ERROR=-180
SLAVE_BLACKLIST_ERROR=-190
NOT_FOUND_DNS_REGISTER=-200
UNREGISTERED_MAC_ERROR=-300
UNKNOWN_NAME_ERROR=-400

class DnsmasqManager:

	def __init__(self):
		#Load template file
		self.tpl_env = Environment(loader=FileSystemLoader('/usr/share/n4d/templates/dnsmasq'))
		self.dynamicconfpath = "/var/lib/dnsmasq/"
		self.dnsfile = self.dynamicconfpath+"hosts/reg" # Format file =====> HOSTIP {HOST_PREFIX}NUMBER_PC_REGISTERED{INTERNAL_DOMAIN}
		self.pathfile = self.dynamicconfpath+"macs/all-hosts" # Format file ======> dhcp-host=MAC_PC,HOSTIP,{HOST_PREFIX}NUMBER_PC_REGISTERED{INTERNAL_DOMAIN}
		self.locktocken = "/tmp/lockmacregister"
		self.leases = "/var/lib/misc/dnsmasq.leases"
		self.backup_files=["/etc/dnsmasq.conf"]
		self.backup_dirs=[self.dynamicconfpath,"/etc/dnsmasq.d/","/etc/lliurex-guard/"]
		self.blacklist_path="/etc/lliurex-guard/blacklist"
		self.blacklist_d_path="/etc/lliurex-guard/blacklist.d"
		self.whitelist_path="/etc/lliurex-guard/whitelist"
		self.whitelist_d_path="/etc/lliurex-guard/whitelist.d"
		self.extradnspath = '/var/lib/dnsmasq/config/extra-dns'
		self.path_nodes_center_model = '/var/lib/dnsmasq/config/center_servers'
		self.n4dCore=n4dCore.Core.get_core()
	#def init
	
	def startup(self,options):
		# executed when launching n4d
		pass
		
	#def startup

	def apt(self):
		# executed after apt operations
		pass
		
	#def apt
	
	# service test and backup functions #
	
	def test(self):

		return n4d.responses.build_successful_call_response()
	#pass
		
	#def test
	def makedir(self,dir=None):
		if not os.path.isdir(dir):
			os.makedirs(dir)
		return [True]

	#def get_time
	def get_time(self):

		return get_backup_name("Dnsmasq")

	#def backup
	def backup(self,dir="/backup"):
		try:
			self.makedir(dir)
		except:
			return n4d.responses.build_failed_call_response(MKDIR_ERROR)

		file_path=dir+"/"+self.get_time()     
		try:
			tar=tarfile.open(file_path,"w:gz")
			for f in self.backup_files:               
				if os.path.exists(f):
					tar.add(f)

			for d in self.backup_dirs:
				if os.path.exists(d):
					tar.add(d)
			tar.close()
		except:
			return n4d.responses.build_failed_call_response(OPEN_TAR_ERROR)
			
		#return [True,file_path]
		return n4d.responses.build_successful_call_response(file_path)

			
		
	#def restore
	def restore(self,file_path=None):

		if file_path==None:
			dir="/backup"
			for f in sorted(os.listdir(dir),reverse=True):
				if "Dnsmasq" in f:
					file_path=dir+"/"+f
					break

		if os.path.exists(file_path):
			try:
				tmp_dir=tempfile.mkdtemp()
			except:
				return n4d.responses.build_failed_call_response(MKDIR_ERROR)

			try:
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close()
			except:
				return n4d.responses.build_failed_call_response(OPEN_TAR_ERROR)

			for f in self.backup_files:
				tmp_path=tmp_dir+f
				if os.path.exists(tmp_path):
					shutil.copy(tmp_path,f)

			#FIX for centralized services in Xenial
			version=objects["ServerBackupManager"].restoring_version
			majorBackupVersion=int(version[0:version.find('.')])
			for d in self.backup_dirs:
				tmp_path=tmp_dir+d
				if os.path.exists(tmp_path):
					self.makedir(d)
					if d == self.dynamicconfpath and majorBackupVersion<=15:
						#Read tmpdir and exclude centralized services 
						#centralizedServices=objects["VariablesManager"].get_variable('SLAVE_BLACKLIST')
						centralizedServices=self.n4dCore.get_variable('SLAVE_BLACKLIST')
						configTmpDir=tmp_path+"config"
						configDir=d+"config"
						for cnameFile in os.listdir(configDir):
							for service in list(centralizedServices.values()):
								serviceStr=str(service)
								if cnameFile in serviceStr:
									self.restore_as_centralized(cnameFile,configDir,configTmpDir)
									break
					else:
						if d =="/etc/lliurex-guard/":
							if os.path.exists(self.blacklist_path):
								cmd="rm -f "+ self.blacklist_path+"/*"
								os.system(cmd)
							if os.path.exists(self.blacklist_d_path):
								cmd="rm -f "+ self.blacklist_d_path+"/*"
								os.system(cmd)
							if os.path.exists(self.whitelist_path):
								cmd="rm -f "+ self.whitelist_path+"/*"
								os.system(cmd)
							if os.path.exists(self.whitelist_d_path):
								cmd="rm -f "+ self.whitelist_d_path+"/*"
								os.system(cmd)	
						
						cmd="cp -r " + tmp_path +"/* "  + d
						os.system(cmd)
						#Add alias for admin-center if backup version<=15
			if majorBackupVersion<=15:
				self.add_alias("admin-center")
			os.system("systemctl restart dnsmasq")
			return n4d.responses.build_successful_call_response()
		else:
			return n4d.responses.build_failed_call_response(FILE_NOT_FOUND_ERROR)

			
	def restore_as_centralized (self,cnameFile=None,dest_dir=None,tmp_path=None):
		cnameRealPath=dest_dir + '/' + cnameFile
		if os.path.isfile(cnameRealPath):
			cmd="cp " + cnameRealPath + " " + tmp_path
			os.system(cmd)
		#elif  objects["VariablesManager"].get_variable("MASTER_SERVER_IP"):
		elif  self.n4dCore.get_variable("MASTER_SERVER_IP"):
			os.remove(cnameFile)

	def has_name(self,mac):
		
		try:
			registerfile = open(self.pathfile,'r')
			lines=registerfile.readlines()
			registerfile.close()
			for line in lines:
				if mac in line:
					#new_content.append("dhcp-host=" + mac + "," + new_ip + ","+ new_hostname +"\n")
					tmp=line.split("dhcp-host=")[1]
					mac,ip,hostname=tmp.split[","]
				return n4d.responses.build_successful_call_response(hostname.strip())
				
			return n4d.responses.build_failed_call_response(UNREGISTERED_MAC_ERROR,"MAC not registered")
		except Exception as e:
			return n4d.responses.build_failed_call_response(UNKNOWN_NAME_ERROR,str(e))
	#def has_name

	def add_node_center_model(self, hostname, ip ):

		#internal_domain = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		internal_domain = self.n4dCore.get_variable('INTERNAL_DOMAIN').get('result','')
		content = []
		if os.path.exists(self.path_nodes_center_model):
			with open(self.path_nodes_center_model, 'r') as fd:
				content = [ line for line in fd.readlines() if not line.strip().endswith(ip) ]
		if internal_domain is not None:
			if hostname == '':
				servername = internal_domain
			else:
				servername = hostname + '.' + internal_domain if internal_domain is not None else hostname
		if servername is None:
			return n4d.responses.build_failed_call_response(INTERNAL_DOMAIN_UNDEFINED_ERROR)

		content.append('server=/{server}/{ip}'.format(ip=ip,server=servername))
		
		with open(self.path_nodes_center_model, 'w') as fd:
			fd.writelines(content)

		return n4d.responses.build_successful_call_response()
	#def add_node_replication

	def set_dns_external(self,dnsexternal):
		list_variables = {}
		template_extradns = self.tpl_env.get_template("extra-dns")

		#list_variables['DNS_EXTERNAL'] = objects['VariablesManager'].get_variable('DNS_EXTERNAL')
		#list_variables['DNS_EXTERNAL'] = self.n4dCore.get_variable('DNS_EXTERNAL')
		#status,list_variables['DNS_EXTERNAL'] = objects['VariablesManager'].init_variable('DNS_EXTERNAL',{'DNS':dnsexternal})	
		self.n4dCore.set_variable('DNS_EXTERNAL',dnsexternal)
		list_variables['DNS_EXTERNAL'] = self.n4dCore.get_variable('DNS_EXTERNAL').get('return',None)
		with tempfile.NamedTemporaryFile('w',delete=False) as new_export_file:
				#new_export_file.write( template_extradns.render(list_variables).encode('UTF-8') )
			new_export_file.write("%s"%template_extradns.render(list_variables) )
			tmpfilepath = new_export_file.name 
		n4d_mv(tmpfilepath, self.extradnspath, True, 'root', 'root', '0644', False )
		return n4d.responses.build_successful_call_response()
	#def set_dns_external
	
	def configure_service(self,domain):
		#status,list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].init_variable('INTERNAL_DOMAIN',{'DOMAIN':domain})
		self.n4dCore.set_variable('INTERNAL_DOMAIN',domain)
		self.n4dCore.set_variable('MAIN_DOMAIN','lliurex')
		result = self.set_internal_domain(domain)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(CONFIGURE_INTERNAL_DOMAIN_ERROR)
		result = self.load_exports()
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(CONFIGURE_LOAD_EXPORTS_ERROR)
		return n4d.responses.build_successful_call_response()
	#def  config_service
	
	def add_alias(self,alias):
		template_cname = self.tpl_env.get_template("cname-server")
		list_variables = {}
		#get INTERNAL_DOMAIN
		#list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		list_variables['INTERNAL_DOMAIN'] = self.n4dCore.get_variable('INTERNAL_DOMAIN').get('return',None)
		#If INT_DOMAIN is not defined return an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return n4d.responses.build_failed_call_response(INTERNAL_DOMAIN_VAR_ERROR)
		#get HOSTNAME
		list_variables['HOSTNAME'] = self.n4dCore.get_variable('HOSTNAME').get('return',None)
		#If INT_DOMAIN is not defined return an error
		if  list_variables['HOSTNAME'] == None:
			return n4d.responses.build_failed_call_response(HOSTNAME_VAR_ERROR)
		
		#Add alias to SRV_ALIAS
		#Obtains actual SRV_ALIAS variable
		#list_variables['SRV_ALIAS'] = objects['VariablesManager'].get_variable('SRV_ALIAS')
		list_variables['SRV_ALIAS'] = self.n4dCore.get_variable('SRV_ALIAS').get('return',{})
		#Add new alias
		if list_variables['SRV_ALIAS'] ==None:
			list_variables['SRV_ALIAS']=[]
		list_variables['SRV_ALIAS'].append(alias)
		#Save new values
		#status,list_variables['SRV_ALIAS'] = objects['VariablesManager'].init_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']})
		#self.n4dCore.set_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']})
		self.n4dCore.set_variable('SRV_ALIAS',list_variables['SRV_ALIAS'])
		list_variables['SRV_ALIAS'] = self.n4dCore.get_variable('SRV_ALIAS').get('return',{})
		#lalias = self.n4dCore.set_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']}).get('return',None)
		#list_variables['SRV_ALIAS'] = self.n4dCore.set_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']}).get('return',None)
		#return {'status':True,'msg':'Set server name succesfully'}
		
		#Encode vars to UTF-8
		string_template = template_cname.render(list_variables)
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		#shutil.move(tmpfilepath,'/etc/dnsmasq.conf')
		n4d_mv(tmpfilepath,'/var/lib/dnsmasq/config/cname-server',True,'root','root','0644',False )
		self.reboot_dhcpd()
		return n4d.responses.build_successful_call_response()
	#def  add_alias
	
	def remove_alias(self,alias):
		template_cname = self.tpl_env.get_template("cname-server")
		list_variables = {}
		#get INTERNAL_DOMAIN
		#list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		list_variables['INTERNAL_DOMAIN'] = self.n4dCore.get_variable('INTERNAL_DOMAIN').get('return',None)
		#If INT_DOMAIN is not defined return an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return n4d.responses.build_failed_call_response(INTERNAL_DOMAIN_VAR_ERROR)

		#get HOSTNAME
		#list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		list_variables['HOSTNAME'] = self.n4dCore.get_variable('HOSTNAME').get('return',None)
		#If INT_DOMAIN is not defined return an error
		if  list_variables['HOSTNAME'] == None:
			return n4d.responses.build_failed_call_response(HOSTNAME_VAR_ERROR)
		
		#Add alias to SRV_ALIAS
		#Obtains actual SRV_ALIAS variable
		#list_variables['SRV_ALIAS'] = objects['VariablesManager'].get_variable('SRV_ALIAS')
		list_variables['SRV_ALIAS'] = self.n4dCore.get_variable('SRV_ALIAS').get('return',[])
		#Add new alias
		if list_variables['SRV_ALIAS'] == None:
			return n4d.responses.build_failed_call_response(SRV_ALIAS_ERROR)
		if alias in list_variables['SRV_ALIAS']:
			list_variables['SRV_ALIAS'].remove(alias)
		else:
			return n4d.responses.build_failed_call_response(ALIAS_ERROR)
		#Save new values
		#status,list_variables['SRV_ALIAS'] = objects['VariablesManager'].init_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']})
		self.n4dCore.set_variable('SRV_ALIAS',list_variables['SRV_ALIAS'])
		list_variables['SRV_ALIAS'] = self.n4dCore.get_variable('SRV_ALIAS').get('return',[])
		#return {'status':True,'msg':'Set server name succesfully'}
		
		#Encode vars to UTF-8
		string_template = template_cname.render(list_variables)
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		#shutil.move(tmpfilepath,'/etc/dnsmasq.conf')
		n4d_mv(tmpfilepath,'/var/lib/dnsmasq/config/cname-server',True,'root','root','0644',False )
		self.reboot_dhcpd()
		return n4d.responses.build_successful_call_response()
	#def  config_service
	
	'''
	def set_srv_name(self,name):
		template_cname = self.tpl_env.get_template("cname-server")
		list_variables = {}
		#get INTERNAL_DOMAIN
		list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		#If INT_DOMAIN is not defined return an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return {'status':False,'msg':'Variable INTERNAL_DOMAIN not defined'}

		#Inicialize SRV_NAME
		status,list_variables['SRV_NAME'] = objects['VariablesManager'].init_variable('SRV_NAME',{'NAME':name})
		#return {'status':True,'msg':'Set server name succesfully'}
		
		#Encode vars to UTF-8
		string_template = template_cname.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		#shutil.move(tmpfilepath,'/etc/dnsmasq.conf')
		n4d_mv(tmpfilepath,'/var/lib/dnsmasq/config/cname-server',True,'root','root','0644',False )
		return {'status':True,'msg':'SRV_NAME changed'}
	'''
	
	def set_internal_domain(self,domain):
		#list_variables = {}
		#Get HOSTNAME
		#list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		try:
			self.n4dCore.get_variable("HOSTNAME")
		except:
			return n4d.responses.build_failed_call_response(HOSTNAME_VAR_ERROR)
		#Set INTERNAL_DOMAIN with args values
		self.n4dCore.set_variable('INTERNAL_DOMAIN',domain)
		#status,list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].init_variable('INTERNAL_DOMAIN',{'DOMAIN':domain})
		return n4d.responses.build_successful_call_response()
		
	def set_main_domain(self,domain):
			#		list_variables = {}
		#Get HOSTNAME
		#list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		try:
		#If variable MAIN_DOMAIN is not defined calculate it with args values
			if not self.n4dCore.get_variable("HOSTNAME"):
				return n4d.responses.build_failed_call_response(HOSTNAME_VAR_ERROR)
		except:
			return n4d.responses.build_failed_call_response(HOSTNAME_VAR_ERROR)
		#Set MAIN_DOMAIN with args values
		self.n4dCore.set_variable('MAIN_DOMAIN',domain)
		return n4d.responses.build_successful_call_response()

	def load_exports(self):
		#Get template

		template_list = []
		template_list.append({'template': self.tpl_env.get_template("dnsmasq.conf") , 'path' : '/etc/dnsmasq.conf' })
		template_list.append({'template': self.tpl_env.get_template("cname-server") , 'path' : '/var/lib/dnsmasq/config/cname-server' })
		template_list.append({'template': self.tpl_env.get_template("server") , 'path' : '/var/lib/dnsmasq/hosts/server' })
		template_list.append({'template': self.tpl_env.get_template("dhclient.conf") , 'path' : '/etc/dhcp/dhclient.conf' })
		template_cname = self.tpl_env.get_template("cname-server")
		template_server = self.tpl_env.get_template("server")
		template_dhclientconf = self.tpl_env.get_template("dhclient.conf")

		query_variables = ['INTERNAL_INTERFACE','INTERNAL_NETWORK','INTERNAL_MASK','INTERNAL_DOMAIN','SRV_IP','HOSTNAME', 'INTERFACE_REPLICATION']
		non_check_variables = ['INTERFACE_REPLICATION']
		#list_variables = objects['VariablesManager'].get_variable_list(query_variables)
		list_variables = self.n4dCore.get_variable_list(query_variables)['return']

		# Check exists variables
		for variable in query_variables:
			if variable in non_check_variables:
				continue
			if list_variables.get(variable,False)==False:  #variable in list_variables and list_variables[variable] is not None ):
				return n4d.responses.build_failed_call_response(UNDEFINED_VAR_ERROR)

		if list_variables.get('INTERFACE_REPLICATION',None):
			result = self.n4dCore.get_plugin('NetworkManager').get_replication_network()
			if result['status']==0:
				list_variables['REPLICATION_NETWORK'] = result['return']

		dranges=dhcpranges.DhcpRanges()

		query_variables = {
			#'DHCP_ENABLE': {'ENABLE':'True'},
			#'DHCP_LEASE_TIME': {'LEASE_TIME':12},
			#'DHCP_DENY_UNKNOWN_CLIENTS': {'DENY_UNKNOWN':'no'},
			#'DHCP_HOST_MAX': {'HOST_MAX':80},
			#'DHCP_FIRST_IP': {'NETWORK':list_variables['INTERNAL_NETWORK'],'MASK':list_variables['INTERNAL_MASK']},
			#'DHCP_LAST_IP': {'NETWORK':list_variables['INTERNAL_NETWORK'],'MASK':list_variables['INTERNAL_MASK']},
			#'DNS_HOSTNAME_PREFIX': {'PREFIX':'llx-'},
			#'DNS_UNREG_HOSTNAME_PREFIX':{'PREFIX':'host-'}
			'DHCP_ENABLE': 'True',
			'DHCP_LEASE_TIME': 12,
			'DHCP_DENY_UNKNOWN_CLIENTS': 'no',
			'DHCP_HOST_MAX': 80,
			'DHCP_FIRST_IP': dranges.init_dhcp_first({"NETWORK":list_variables["INTERNAL_NETWORK"],"MASK":list_variables["INTERNAL_MASK"]}),
			'DHCP_LAST_IP': dranges.init_dhcp_last({"NETWORK":list_variables["INTERNAL_NETWORK"],"MASK":list_variables["INTERNAL_MASK"]}),
			'DNS_HOSTNAME_PREFIX': 'llx-',
			'DNS_UNREG_HOSTNAME_PREFIX':'host-',
			"SRV_ALIAS":["cups","www","ntp","share","srv","servidor","jclic-aula","lliurexlab","error","ipxboot","admin-center"]
		}

		for variable in query_variables:
			self.n4dCore.set_variable(variable, query_variables[variable])
		
		list_variables.update(query_variables)
	
		for template_info in template_list:
			with tempfile.NamedTemporaryFile('w',delete=False) as new_export_file:
				#new_export_file.write( template_info['template'].render(list_variables).encode('UTF-8') )
				new_export_file.write( "%s"%template_info['template'].render(list_variables) )
				tmpfilepath = new_export_file.name 
			n4d_mv(tmpfilepath, template_info['path'], True, 'root', 'root', '0644', False )
		
		return n4d.responses.build_successful_call_response()
	#def load_exports
	
	def set_dns_master_services(self):

		ip = '10.3.0.254'
		listservices = []
		#listnames = objects['VariablesManager'].get_variable('SLAVE_BLACKLIST')#{'':['']}
		listnames = self.n4dCore.get_variable('SLAVE_BLACKLIST').get('return',{})
		if not listnames:
			return n4d.responses.build_failed_call_response(SLAVE_BLACKLIST_ERROR)
		allok = True
		msg=[]

		for x in listnames.keys():
			listservices.extend(listnames[x])

		for service in listservices:
			result = self.set_external_dns_entry(service,ip)
			if not result['status']:
				allok = False
				msg.append(result['msg'])
		return n4d.responses.build_successful_call_response()

	#def set_dns_master_services

	def set_internal_dns_entry(self,name):
		try:
			internal = self.n4dCore.get_variable('INTERNAL_DOMAIN').get('return','')
			main_domain = self.n4dCore.get_variable('MAIN_DOMAIN').get('return','')
			if main_domain==None:
				main_domain="lliurex"
			hostname = self.n4dCore.get_variable('HOSTNAME').get('return','')
			f = open(self.dynamicconfpath+'config/'+name,'w')
			f.write("cname="+name+"."+ internal +","+ hostname + "."+internal+"\n")
			#cname for service.machine.main_domain
			f.write("cname="+name+"."+hostname+"."+main_domain+","+ hostname + "."+internal)
			f.close()
			if os.path.exists(self.dynamicconfpath+'hosts/'+name):
				os.remove(self.dynamicconfpath+'hosts/'+name)
			return n4d.responses.build_successful_call_response()
		except Exception as e:
			print(e)
			return n4d.responses.build_failed_call_response(SET_INTERNAL_DNS_ERROR)

	def set_external_dns_entry(self,name,ip):
		try:
			f = open(self.dynamicconfpath+'hosts/'+name,'w')
			f.write(ip + ' '+ name)
			f.close()
			if os.path.exists(self.dynamicconfpath+'config/'+name):
				os.remove(self.dynamicconfpath+'config/'+name)
			return n4d.responses.build_successful_call_response()
		except Exception as e:
			return n4d.responses.build_failed_call_response(SET_EXTERNAL_DNS_ERROR)

	#def set_dns_entry

	def reboot_dhcpd(self):
		#Restart dhcpd service
		subprocess.Popen(['systemctl','restart','dnsmasq'],stdout=subprocess.PIPE).communicate()
		return n4d.responses.build_successful_call_response()
	#def reboot_dhcpd


	def get_available_id_list(self):
		new_hostname_prefix = self.n4dCore.get_variable('DNS_HOSTNAME_PREFIX').get('return','')
		new_hostname_sufix = self.n4dCore.get_variable('INTERNAL_DOMAIN').get('return','')
		var_dhcp_first=self.n4dCore.get_variable('DHCP_FIRST_IP')
		var_dhcp_last=self.n4dCore.get_variable('DHCP_LAST_IP')
		(dhcp_first,dhcp_last)=(None,None)
		if var_dhcp_first['status']==0:
			dhcp_first=var_dhcp_first.get('return',None)
		if var_dhcp_last['status']==0:
			dhcp_last=var_dhcp_last.get('return',None)
		if dhcp_first and dhcp_last:
			lavailable = range(1,self._subtraction_ip(dhcp_first,dhcp_last))
		else:
			return n4d.responses.build_failed_call_response(NO_DHCP_INFO_ERROR)

		default = self._get_first_id_available(new_hostname_prefix,new_hostname_sufix)
		if int(default) > int(lavailable[-1]):
			default = lavailable[-1]
		return n4d.responses.build_successful_call_response({'result':lavailable,'default':default})
	#def get_available_id_list
	
	def remove_register(self,mac):
		if not os.path.exists(self.locktocken):
			open(self.locktocken,'a')
		else:
			return n4d.responses.build_failed_call_response(SERVER_LOCKED_ERROR)
		registerfile = open(self.pathfile,'r')
		content = registerfile.readlines()
		registerfile.close()
		found = False
		found_str = ""
		new_content = []
		#dhcp-host=00:0F:FE:C3:D9:EC,10.0.2.1,llx-pc01
		for line in content:
			try:
				auxline = line.strip('\n')
				auxline = auxline.split('=')[1]
				lmac,lip,lhostname = auxline.split(',')
			except:
				continue
			if lmac == mac :
				found = True
				found_str = lip + " " + lhostname
			else:
				new_content.append(line)
		if not found :
			os.remove(self.locktocken)
			return n4d.responses.build_failed_call_response(UNREGISTERED_MAC_ERROR)
		else:
			#mac founded
			registerfile = open(self.pathfile,'w')
			for line in new_content:
				registerfile.write(line)
			registerfile.close()
			
			new_content = []
			dnsfile = open(self.dnsfile,'r')
			content = dnsfile.readlines()
			dnsfile.close()
			for line in content:
				line_striped = line.strip()
				if (line_striped != found_str):
					new_content.append(line)
			
			dnsfile = open(self.dnsfile,'w')
			for line in new_content:
				dnsfile.write(line)
			dnsfile.close()
			
			os.remove(self.locktocken)
			return n4d.responses.build_successful_call_response('MAC '+mac+' has been removed')
	#def register_machine
	
	def register_machine(self,id,mac,isteacher):
		#Check if this process is running
		if not os.path.exists(self.locktocken):
			open(self.locktocken,'a')
		else:
			return n4d.responses.build_failed_call_response(UNREGISTERED_MAC_ERROR)

		new_hostname_prefix = self.n4dCore.get_variable('DNS_HOSTNAME_PREFIX')
		new_hostname_sufix = self.n4Core.get_variable('INTERNAL_DOMAIN')
		if int(id) < 10 :
			new_hostname = new_hostname_prefix + "0" + id + new_hostname_sufix
		else:
			new_hostname = new_hostname_prefix + id + new_hostname_sufix
		ip_base = self.n4dCore.get_variable('INTERNAL_NETWORK')
		new_ip = self._increment_ip(ip_base,id)
		if new_ip == None:
			os.remove(self.locktocken)
			return n4d.responses.build_failed_call_response(UNKNOWN_IP_ERROR)
		# dhcp-host=MAC_PC,HOSTIP,{HOST_PREFIX}NUMBER_PC_REGISTERED{INTERNAL_DOMAIN}
		new_content = []
		registerfile = open(self.pathfile,'r')
		content = registerfile.readlines()		
		for line in content:
			try:
				auxline = line.split('=')[1]
				lmac,lip,lhostname = auxline.split(',')
				lhostname = lhostname.strip()
			except:
				continue
			if new_hostname != lhostname and lmac != mac:
				new_content.append(line)
		registerfile.close()
		
		new_content.append("dhcp-host=" + mac + "," + new_ip + ","+ new_hostname +"\n")
		registerfile = open(self.pathfile,'w')
		for line in new_content:
			registerfile.write(line)
		registerfile.close()
		
		# HOSTIP {HOST_PREFIX}NUMBER_PC_REGISTERED{INTERNAL_DOMAIN}
		new_content = []
		dnsfile = open(self.dnsfile,'r')
		content = dnsfile.readlines()
		for line in content:
			try:
				lip,lhostname = line.split(' ')
				lhostname = lhostname.strip()
			except:
				continue
			if new_hostname != lhostname and lip != new_ip:
				new_content.append(line)
		dnsfile.close()
		
		new_content.append(new_ip + " " + new_hostname + "\n")
		dnsfile = open(self.dnsfile,'w')
		for line in new_content:
			dnsfile.write(line)
		dnsfile.close()
		
		os.remove(self.locktocken)
		#return {'status':True,'result':'MAC '+ mac + ' has been registered with id ' + id }
		return n4d.responses.build_successful_call_response("MAC %s has been registered with id %s"%(mac,id))
	#def register_machine
	

	def get_host_from_ip(self, ip):
		import re
		with open(self.dnsfile,'r', encoding='utf-8') as fd:
			hosts = fd.readlines()
		for x in hosts:
			matching = re.match("{ip}\s+(.+)".format(ip), x)
			if matching is not None:
				return n4d.responses.build_successful_call_response(matching.group(1))
		return n4d.responses.build_failed_call_response(DnsmasqManager.NOT_FOUND_DNS_REGISTER)

	#def get_host_from_ip

	
	'''
	Internal method
	'''
	
	def _subtraction_ip(self,a,b):
		try:
			list_a = a.split('.')
		except:
			print(a)
		list_a.reverse()
		list_b = b.split('.')
		list_b.reverse()
		total = 0
		for i in range(len(list_a)):
			if i > 0 :
				total += (int(list_b[i]) - int(list_a[i])) * (256 ** i)
			else:
				total += int(list_b[i]) - int(list_a[i]) + 1
		return total
	#def _subtraction_ip
	
	def _get_ip_by_mac(self, mac):
		f = open(self.leases,'r')
		all_lines = f.readlines()
		ip = ""
		for line in all_lines:
			try:
				list_params = line.split(' ')
				if (list_params[1] == mac ):
					ip = list_params[2]
					break
			except Exception as e:
				pass
		f.close()
		if (ip == ""):
			return None
		else:
			return ip
	#def _get_ip_by_mac
	
	def _get_first_id_available(self,head,foot):
		f = open(self.dnsfile,'r')
		lines = f.readlines()
		final = []
		for x in lines:
			s = re.search(".*"+head+"(\d*)"+foot+".*",x)
			if s != None:
				final.append(s.group(1))
		if (len(final) == 0) or (int(final[0]) > 1):
			return 0
		z = 0
		found = False
		for x in final:
			z += 1
			if z != int(x):
				found = True
				break
		if not found:
			z += 1
		return z
	#def _get_first_id_available
	
	def _increment_ip(self,base,num):
		try:
			ip = base.split('.')
			last_octect = ip[-1]
			x = int(last_octect) + int(num)
			t_octect = x / 256
			l_octect = x % 256
			calculed_ip =  ip[0]+"."+ip[1]+"."+str(int(ip[2])+t_octect)+ "." + str(l_octect)
			return calculed_ip
		except:
			return None	



#class Dnsmasq
