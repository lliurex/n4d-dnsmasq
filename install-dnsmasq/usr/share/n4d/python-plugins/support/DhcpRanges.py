
class DhcpRanges:

	def init_dhcp_first(self,args):
		DEBUG=0;
		try:
			network = args['NETWORK']
			mask = args['MASK']
		except:
			network = "10.10.0.30"
			mask = 22

		try:
			self.tpc_reserv = args['RESERVATION']
		except:
			self.tpc_reserv = 5;


		# pasamos ip -> binario
		netbinary=self.to_bin(network);
		# mas alla de la mascara, sustituimos por 0's
		netbinary=netbinary[:mask]+netbinary[mask:].translate(str.maketrans('1','0'));
		# generamos wildcard como 0's y mas alla de la mascara 1's
		wildcard='';
		for i in range(mask,32):
			wildcard+='1';
		wildcard=wildcard.zfill(32);
		# para generar binario de la mascara, invertimos wildcard
		maskbinary=wildcard.translate(str.maketrans('10','01'));
		# calculamos numero maximo de host en la red como el valor del numero (binario) de la mascara -2 host (dir red, dir broadcast)
		total_hosts=int(wildcard,2)+1-2;
		# calculo de direcciones reservadas en funcion del size de la red
		reservas=self.calc_reservas(total_hosts);
		num_hosts=total_hosts-reservas;
		# el primer host es el siguiente despues del valor de red mas las reservas, 
		print(netbinary)
		print(type(netbinary))
		print(reservas)
		print(type(reservas))
		first_host=bin(int(netbinary,2)+1+reservas)[2:].zfill(32);

		# calculo de direccion broadcast mediante un OR entre la direccion de red y la wildcard
		broadcast=bin(int(netbinary,2) | int(wildcard,2))[2:].zfill(32);
		# el ultimo host calculado como uno menos de el valor de broadcast 
		last_host=bin(int(broadcast,2)-1)[2:].zfill(32);
		
		return self.to_ip(first_host)
		
	#def init first

	def init_dhcp_last(self,args):
		

		try:
			network = args['NETWORK']
			mask = args['MASK']
		except:
			network = "10.10.0.30"
			mask = 22

		try:
			self.tpc_reserv = args['RESERVATION']
		except:
			self.tpc_reserv = 5;


		# pasamos ip -> binario
		netbinary=self.to_bin(network);
		# mas alla de la mascara, sustituimos por 0's
		netbinary=netbinary[:mask]+netbinary[mask:].translate(str.maketrans('1','0'));
		# generamos wildcard como 0's y mas alla de la mascara 1's
		wildcard='';
		for i in range(mask,32):
			wildcard+='1';
		wildcard=wildcard.zfill(32);
		# para generar binario de la mascara, invertimos wildcard
		maskbinary=wildcard.translate(str.maketrans('10','01'));
		# calculamos numero maximo de host en la red como el valor del numero (binario) de la mascara -2 host (dir red, dir broadcast)
		total_hosts=int(wildcard,2)+1-2;
		# calculo de direcciones reservadas en funcion del size de la red
		reservas=self.calc_reservas(total_hosts);
		num_hosts=total_hosts-reservas;
		# el primer host es el siguiente despues del valor de red
		first_host=bin(int(netbinary,2)+1)[2:].zfill(32);
		# el ultimo host calculado sumando al primero el numero maximo 
		last_host=bin(int(first_host,2)+num_hosts-1)[2:].zfill(32);
		# calculo de direccion broadcast mediante un OR entre la direccion de red y la wildcard
		broadcast=bin(int(netbinary,2) | int(wildcard,2))[2:].zfill(32);

		return self.to_ip(last_host)

	#def init last


	def to_ip(self,ipbin):
		return str(int(ipbin[:8],2))+'.'+str(int(ipbin[8:16],2))+'.'+str(int(ipbin[16:24],2))+'.'+str(int(ipbin[24:32],2));
	#def to_ip

	def to_bin(self,ip):
		net_tuple=ip.split('.');
		ipbin='';
		for i in range(0,4):
			ipbin += str(bin(int(net_tuple[i])))[2:].zfill(8);
		return ipbin;
	#def to_bin

	def calc_reservas(self,num):
		#calcula el numero de reservas segun el rango de red 5%
		return int(num*self.tpc_reserv/100)
	#def calc_reservas
	






