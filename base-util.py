#! /usr/bin/python
import sys
import time
import ast
from src.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from src.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from src.com.citrix.netscaler.nitro.resource.config import lb
from src.com.citrix.netscaler.nitro.resource.config import ns
from src.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from src.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_service_binding import lbvserver_service_binding
from src.com.citrix.netscaler.nitro.resource.config.basic.service import service
from src.com.citrix.netscaler.nitro.resource.config.ns.nsconfig import nsconfig
from src.com.citrix.netscaler.nitro.resource.stat.basic.service_stats import service_stats
from src.com.citrix.netscaler.nitro.resource.stat.lb.lbvserver_stats import lbvserver_stats
from src.com.citrix.netscaler.nitro.resource.stat.system.system_stats import system_stats
from src.com.citrix.netscaler.nitro.resource.config.cache.cacheobject import cacheobject
from timeit import default_timer as timer

class ns_toolz :
	def __init__(self):
		_ip=""
		_username=""
		_password=""
		_mode=""
		_vserver_name=''
		_service_name=''
		_vserver_ip=''
		_server_ip=''


	@staticmethod
	def main(cls, args_):
		print 'runnnig ns_toolz...'
		# service_name = ['web-blue-80','web-red-80','web-green-80']
		# server_ip = ['10.0.17.11','10.0.17.12','10.0.17.13']
		vproto = 'http'
		rproto = 'http'
		vport = '80'
		rport =  vport
		mgmt_proto = 'http'
		refresh_sts = 5 
		timeout = 180
		start_script = timer()

		if len(sys.argv) < 6 and len(sys.argv) != 9 :
			print("Usage: ns_toolz <ip> <username> <password> <mode> <vserver_name> [<service_name>]")
			return

		input_from_cli = ns_toolz()
		input_from_cli.ip = args_[1]
		input_from_cli.username = args_[2]
		input_from_cli.password = args_[3]
		input_from_cli.mode = args_[4]
		input_from_cli.vserver_name = args_[5]

		if len(sys.argv) > 6 : 
			input_from_cli.service_name = args_[6].split(',')
			if len(sys.argv) > 7 : 
				input_from_cli.vserver_ip = args_[7]
				input_from_cli.server_ip = args_[8].split(',')
		try:
			ns_session = establish_session(input_from_cli.ip,mgmt_proto,timeout)
		except:
			print 'Not able to reach/auth %s ' % str(input_from_cli.ip)

		if input_from_cli.mode == 'get' :
			while True :
				get_stat_lbvserver(ns_session, input_from_cli.vserver_name)
				if len(sys.argv) > 6 : get_stat_service(ns_session, input_from_cli.service_name)
				time.sleep(refresh_sts)
		elif input_from_cli.mode == 'add' :
			add_lbvserver(ns_session, input_from_cli.vserver_name, input_from_cli.vserver_ip, vport, vproto)
			add_service(ns_session, input_from_cli.service_name, rport, rproto, input_from_cli.server_ip)
			addlbvserver_bindings(ns_session,input_from_cli.vserver_name,input_from_cli.service_name)
			ns_session.logout()
		else: 
			pass
		elapsed_time = timer() - start_script
		print 'code execution took %s seconds' % str(elapsed_time)
		print 'bye Mr. Flynn'

def establish_session(ns_host,mgmt_proto,timeout) :
	ns_session = nitro_service(ns_host,mgmt_proto)
	ns_session.set_credential('nsroot','nsroot')
	ns_session.set_timeout(timeout)
	return(ns_session)

def add_lbvserver(ns_session, vserver_name, vserver_ip, vport, vproto) :
	try :
		obj = lbvserver()			
		obj.set_name(vserver_name)
		obj.set_ipv46(vserver_ip)
		obj.set_port(vport)
		obj.set_servicetype(lbvserver.servicetype.HTTP)
		response = lbvserver.add(ns_session, obj)
		print("add_lbvserver - Done")
		if response.severity and response.severity =="WARNING" :
			print("\tWarning : " + response.message)
	except Exception as e:
		print("Exception::add_lbvserver::message="+str(e.args))

def add_service(ns_session, service_name, rport, rproto, server_ip) :
	ns_service = [i for i in range(len(service_name))]
	try :
		for item in range(len(service_name)):
			ns_service[item] = service()
			ns_service[item].set_name(service_name[item])
			ns_service[item].set_ip(server_ip[item])
			ns_service[item].set_port(rport)
			ns_service[item].set_servicetype(rproto)
			ns_service[item].add(ns_session, ns_service[item])               
		print("add_service - Done")
	except Exception as e:
		print("Exception::add_service::message="+str(e.args))


def addlbvserver_bindings(ns_session,vserver_name, service_name) :
	obj = [i for i in range(len(service_name))]
	try :
		for item in range(len(service_name)):
			obj[item] = lbvserver_service_binding()
			obj[item].set_name(vserver_name)
			obj[item].set_servicename(service_name[item])
			obj[item].set_weight(1)
			lbvserver_service_binding.add(ns_session, obj[item])
			print("addlbvserver_bindings - Done")
	except Exception as e:
		print("Exception::addlbvserver_bindings::message="+str(e.args))

def get_stat_lbvserver(ns_session, vserver_name):
	try:
		obj = lbvserver_stats.get(ns_session, vserver_name)
		reqrate = obj.get_requestsrate()
		resrate = obj.get_responsesrate()
		cur_svr_conns = obj.cursrvrconnections
		cur_cln_conns = obj.curclntconnections
		tot_req_bytes = obj.totalrequestbytes
		tot_res_bytes = obj.totalresponsebytes
		tot_req = obj.totalrequests
		tot_res = obj.totalresponses
		print 'VSERVER stats [%s] ' % vserver_name
		print 'request rate:    %s req/s\t\t response rate: \t%s req/s' % (str(reqrate),str(resrate))
		print 'cur_svr_ccus:    %s \t\t\t cur_client_ccus: \t%s' % (str(cur_svr_conns),str(cur_cln_conns))
		print 'tot_req:         %s req/s\t\t tot_res: \t\t%s res/s' % (str(tot_req),str(tot_res))
		print 'tot_req_bytes:   %s Kbps\t\t tot_res_bytes: \t%s Kbps\t' % (str("{0:,d}".format(int(tot_req_bytes)/1024)) , str("{0:,d}".format(int(tot_res_bytes)/1024)))
	except Exception as e:
		print("Exception::stat_lbvserver::message="+str(e.args))
	print ''

def get_stat_service(ns_session, service_name):
	obj = [i for i in range(len(service_name))]
	try:
		for item in range(len(service_name)):
			obj[item]= service_stats.get(ns_session, service_name[item])
			reqrate = obj[item].get_requestsrate()
			resrate = obj[item].get_responsesrate()
			cur_svr_conns = obj[item].cursrvrconnections
			cur_cln_conns = obj[item].curclntconnections
			tot_req_bytes = obj[item].totalrequestbytes
			tot_res_bytes = obj[item].totalresponsebytes
			tot_req = obj[item].totalrequests
			tot_res = obj[item].totalresponses
			print 'SERVICE stats [%s] ' % service_name[item]
			print 'request rate:    %s \t\t response rate: \t%s' % (str(reqrate),str(resrate))
			print 'cur_svr_conns:   %s \t\t cur_cln_conns: \t%s' % (str(cur_svr_conns),str(cur_cln_conns))
			print 'tot_req:         %s \t\t tot_res: \t\t%s' % (str(tot_req),str(tot_res))
			print 'tot_req_bytes:   %s \t tot_res_bytes: \t%s' % (str("{0:,d}".format(tot_req_bytes/1024)), \
			str("{0:,d}".format(tot_res_bytes/1024)))
			print ''
	except Exception as e:
		print("Exception::stat_service::message="+str(e.args))


if __name__ == '__main__':
	try:
		if len(sys.argv) < 6 and len(sys.argv) != 9 :
			sys.exit()
		else:
			ipaddress=sys.argv[1]
			username=sys.argv[2]
			password=sys.argv[3]
			mode=sys.argv[4]
			vserver_name =sys.argv[5]
			if len(sys.argv) > 6 :
				service_name =sys.argv[6]
				if len(sys.argv) > 7 :
					vserver_ip =sys.argv[7]
					server_ip =sys.argv[8]
			ns_toolz().main(ns_toolz(),sys.argv)
	except SystemExit:
		print("Exception::Usage: Usage: ns_toolz <ip> <username> <password> <mode> <vserver_name> [<service_name>]")
