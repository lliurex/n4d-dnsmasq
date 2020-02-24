# npackage example  https://svn.lliurex.net/pandora/n4d-ldap/trunk
# jinja2 http://jinja.pocoo.org/docs/templates

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader
from jinja2 import Template
import tempfile
import shutil
import os
import subprocess

class Dnsmasq:

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

		pass
		
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
			file_path=dir+"/"+self.get_time()     
			tar=tarfile.open(file_path,"w:gz")
				
			for f in self.backup_files:               
				if os.path.exists(f):
					tar.add(f)

			for d in self.backup_dirs:
				if os.path.exists(d):
					tar.add(d)
			tar.close()

			return [True,file_path]

		except Exception as e:
			return [False,str(e)]
			
		
	#def restore
	def restore(self,file_path=None):

		try:                       
			if file_path==None:
				dir="/backup"
				for f in sorted(os.listdir(dir),reverse=True):
					if "Dnsmasq" in f:
						file_path=dir+"/"+f
						break

			if os.path.exists(file_path):
				tmp_dir=tempfile.mkdtemp()
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close()

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
							centralizedServices=objects["VariablesManager"].get_variable('SLAVE_BLACKLIST')
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
				return [True,""]
			else:
				return [False,"Backup file not found"]

		except Exception as e:
			return [False,str(e)]
			
	def restore_as_centralized (self,cnameFile=None,dest_dir=None,tmp_path=None):
		cnameRealPath=dest_dir + '/' + cnameFile
		if os.path.isfile(cnameRealPath):
			cmd="cp " + cnameRealPath + " " + tmp_path
			os.system(cmd)
		elif  objects["VariablesManager"].get_variable("MASTER_SERVER_IP"):
			os.remove(cnameFile)

	def has_name(self,mac):
		pass
	#def has_name

	def add_node_center_model(self, hostname, ip ):

		internal_domain = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		with open(self.path_nodes_center_model, 'r') as fd:
			content = [ line for line in fd.readlines() if not line.strip().endswith(ip) ]
		if internal_domain is not None:
			if hostname == '':
				servername = internal_domain
			else:
				servername = hostname + '.' + internal_domain if internal_domain is not None else hostname
		if servername is None:
			return {'status':False, 'msg':'Internal Domain is not defined'}
		content.append('server=/{server}/{ip}'.format(ip=ip,server=servername))
		
		with open(self.path_nodes_center_model, 'w') as fd:
			fd.writelines(content)

		return {'status': True, 'msg': 'Ok'}
	#def add_node_replication

	def set_dns_external(self,dnsexternal):
		list_variables = {}
		template_extradns = self.tpl_env.get_template("extra-dns")

		list_variables['DNS_EXTERNAL'] = objects['VariablesManager'].get_variable('DNS_EXTERNAL')
		status,list_variables['DNS_EXTERNAL'] = objects['VariablesManager'].init_variable('DNS_EXTERNAL',{'DNS':dnsexternal})	
		with tempfile.NamedTemporaryFile('w',delete=False) as new_export_file:
			new_export_file.write( template_extradns.render(list_variables).encode('UTF-8') )
			tmpfilepath = new_export_file.name 
		n4d_mv(tmpfilepath, self.extradnspath, True, 'root', 'root', '0644', False )
		return {'status':True,'msg':'Set dns external succesfully'}
	#def set_dns_external
	
	def configure_service(self,domain):
		list_variables = {}
		status,list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].init_variable('INTERNAL_DOMAIN',{'DOMAIN':domain})
		result = self.set_internal_domain(domain)
		if not result['status']:
			return result
		result = self.load_exports()
		if not result['status']:
			return result
		return {'status':True,'msg':'SUCCESS'}			
	#def  config_service
	
	def add_alias(self,alias):
		template_cname = self.tpl_env.get_template("cname-server")
		list_variables = {}
		#get INTERNAL_DOMAIN
		list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		#If INT_DOMAIN is not defined return an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return {'status':False,'msg':'Variable INTERNAL_DOMAIN not defined'}
		#get HOSTNAME
		list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		#If INT_DOMAIN is not defined return an error
		if  list_variables['HOSTNAME'] == None:
			return {'status':False,'msg':'Variable HOSTNAME not defined'}			
		
		#Add alias to SRV_ALIAS
		#Obtains actual SRV_ALIAS variable
		list_variables['SRV_ALIAS'] = objects['VariablesManager'].get_variable('SRV_ALIAS')
		#Add new alias
		if list_variables['SRV_ALIAS'] ==None:
			list_variables['SRV_ALIAS']=[]
		list_variables['SRV_ALIAS'].append(alias)
		#Save new values
		status,list_variables['SRV_ALIAS'] = objects['VariablesManager'].init_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']})
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
		return {'status':True,'msg':'SRV_ALIAS changed'}
		self.reboot_dhcpd()
	#def  add_alias
	
	def remove_alias(self,alias):
		template_cname = self.tpl_env.get_template("cname-server")
		list_variables = {}
		#get INTERNAL_DOMAIN
		list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		#If INT_DOMAIN is not defined return an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return {'status':False,'msg':'Variable INTERNAL_DOMAIN not defined'}
		#get HOSTNAME
		list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		#If INT_DOMAIN is not defined return an error
		if  list_variables['HOSTNAME'] == None:
			return {'status':False,'msg':'Variable HOSTNAME not defined'}			
		
		#Add alias to SRV_ALIAS
		#Obtains actual SRV_ALIAS variable
		list_variables['SRV_ALIAS'] = objects['VariablesManager'].get_variable('SRV_ALIAS')
		#Add new alias
		if list_variables['SRV_ALIAS'] == None:
			return {'status':True,'msg':'SRV_ALIAS is empty'}
		if alias in list_variables['SRV_ALIAS']:
			list_variables['SRV_ALIAS'].remove(alias)
		else:
			return {'status':False,'msg': 'alias not found'}
		#Save new values
		status,list_variables['SRV_ALIAS'] = objects['VariablesManager'].init_variable('SRV_ALIAS',{'ALIAS':list_variables['SRV_ALIAS']})
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
		return {'status':True,'msg':'SRV_ALIAS changed'}
		self.reboot_dhcpd()
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
		list_variables = {}
		#Get HOSTNAME
		list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		#If variable INTERNAL_DOMAIN is not defined calculate it with args values
		if  list_variables['HOSTNAME'] == None:
			return {'status':False,'msg':'Variable HOSTNAME is not defined'}
		#Set INTERNAL_DOMAIN with args values
		status,list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].init_variable('INTERNAL_DOMAIN',{'DOMAIN':domain})
		return {'status':True,'msg':'Set internal domain succesfully'}

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
		list_variables = objects['VariablesManager'].get_variable_list(query_variables)

		# Check exists variables
		for variable in query_variables:
			if variable in non_check_variables:
				continue
			if not ( variable in list_variables and list_variables[variable] is not None ):
				return {'status': False, 'msg': 'Variable {variable} not define'.format(variable=variable) }

		if list_variables['INTERFACE_REPLICATION'] is not None:
			result = objects['NetworkManager'].get_replication_network()
			if result['status']:
				list_variables['REPLICATION_NETWORK'] = result['msg']

		query_variables = {
			'DHCP_ENABLE': {'ENABLE':'True'},
			'DHCP_LEASE_TIME': {'LEASE_TIME':12},
			'DHCP_DENY_UNKNOWN_CLIENTS': {'DENY_UNKNOWN':'no'},
			'DHCP_HOST_MAX': {'HOST_MAX':80},
			'DHCP_FIRST_IP': {'NETWORK':list_variables['INTERNAL_NETWORK'],'MASK':list_variables['INTERNAL_MASK']},
			'DHCP_LAST_IP': {'NETWORK':list_variables['INTERNAL_NETWORK'],'MASK':list_variables['INTERNAL_MASK']},
			'DNS_HOSTNAME_PREFIX': {'PREFIX':'llx-'},
			'DNS_UNREG_HOSTNAME_PREFIX':{'PREFIX':'host-'}
		}

		for variable in query_variables:
			list_variables[variable] = objects['VariablesManager'].init_variable(variable, query_variables[variable])
		status,list_variables['SRV_ALIAS'] = objects['VariablesManager'].init_variable('SRV_ALIAS')
	
	
		for template_info in template_list:
			with tempfile.NamedTemporaryFile('w',delete=False) as new_export_file:
				new_export_file.write( template_info['template'].render(list_variables).encode('UTF-8') )
				tmpfilepath = new_export_file.name 
			n4d_mv(tmpfilepath, template_info['path'], True, 'root', 'root', '0644', False )
		
		return {'status':True,'msg':'Service configured'}
	#def load_exports
	
	def set_dns_master_services(self):

		ip = '10.3.0.254'
		listservices = []
		listnames = objects['VariablesManager'].get_variable('SLAVE_BLACKLIST')#{'':['']}
		allok = True
		msg=[]

		for x in listnames.keys():
			listservices.extend(listnames[x])

		for service in listservices:
			result = self.set_external_dns_entry(service,ip)
			if not result['status']:
				allok = False
				msg.append(result['msg'])
		return {'status':allok,'msg':msg}

	#def set_dns_master_services

	def set_internal_dns_entry(self,name):
		try:
			internal = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
			hostname = objects['VariablesManager'].get_variable('HOSTNAME')
			f = open(self.dynamicconfpath+'config/'+name,'w')
			f.write("cname="+name+"."+ internal +","+ hostname + "."+internal)
			f.close()
			if os.path.exists(self.dynamicconfpath+'hosts/'+name):
				os.remove(self.dynamicconfpath+'hosts/'+name)
			return {'status':True,'msg':''}
		except Exception as e:
			return {'status':False,'msg':str(e)}

	def set_external_dns_entry(self,name,ip):
		try:
			f = open(self.dynamicconfpath+'hosts/'+name,'w')
			f.write(ip + ' '+ name)
			f.close()
			if os.path.exists(self.dynamicconfpath+'config/'+name):
				os.remove(self.dynamicconfpath+'config/'+name)
			return {'status':True,'msg':''}
		except Exception as e:
			return {'status':False,'msg':str(e)}	

	#def set_dns_entry

	def reboot_dhcpd(self):
		#Restart dhcpd service
		subprocess.Popen(['systemctl','restart','dnsmasq'],stdout=subprocess.PIPE).communicate()
		return {'status':True,'msg':'DNSMASQ rebooted'}
	#def reboot_dhcpd


	def get_available_id_list(self):
		new_hostname_prefix = objects['VariablesManager'].get_variable('DNS_HOSTNAME_PREFIX')
		new_hostname_sufix = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		lavailable = range(1,self._subtraction_ip(objects['VariablesManager'].get_variable('DHCP_FIRST_IP'),objects['VariablesManager'].get_variable('DHCP_LAST_IP')))
		default = self._get_first_id_available(new_hostname_prefix,new_hostname_sufix)
		if int(default) > int(lavailable[-1]):
			default = lavailable[-1]
		return {'status':True,'result':lavailable,'default':default}
	#def get_available_id_list
	
	def remove_register(self,mac):
		if not os.path.exists(self.locktocken):
			open(self.locktocken,'a')
		else:
			return {'status':False,'msg':'Server is locked now' }
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
			return {'status':False,'result':'MAC ' + mac + ' is not registred' }
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
			return {'status':True,'result':'MAC '+mac+' has been removed' }
	#def register_machine
	
	def register_machine(self,id,mac,isteacher):
		#Check if this process is running
		if not os.path.exists(self.locktocken):
			open(self.locktocken,'a')
		else:
			return {'status':False,'result':'Server is locked now' }

		new_hostname_prefix = objects['VariablesManager'].get_variable('DNS_HOSTNAME_PREFIX')
		new_hostname_sufix = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		if int(id) < 10 :
			new_hostname = new_hostname_prefix + "0" + id + new_hostname_sufix
		else:
			new_hostname = new_hostname_prefix + id + new_hostname_sufix
		ip_base = objects['VariablesManager'].get_variable('INTERNAL_NETWORK')
		new_ip = self._increment_ip(ip_base,id)
		if new_ip == None:
			os.remove(self.locktocken)
			return {'status':False,'result':'Not found ip for ' + new_hostname}
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
		return {'status':True,'result':'MAC '+ mac + ' has been registered with id ' + id }
	#def register_machine
	
	'''
	Internal method
	'''
	
	def _subtraction_ip(self,a,b):
		list_a = a.split('.')
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
