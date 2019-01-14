#!/usr/bin/python
import xmlrpclib

ip_server = '10.0.0.236'
c = xmlrpclib.ServerProxy("https://"+ip_server+":9779")
#c = xmlrpclib.ServerProxy("https://192.168.1.2:9779")
user = ("lliurex","lliurex")

print c.get_methods('Dnsmasq')

#se necesita inicializar previamente las siguientes variables del n4d-network
#SRV_IP
#INTERNAL_NETWORK
#INTERNAL_MASK
#INTERNAL_INTERFACE

print c.configure_service(user,'Dnsmasq','aula1')
print c.set_dns_external(user,'Dnsmasq','172.25.111.4')
