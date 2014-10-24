import os, sys
import base64
import logging
log = logging.getLogger(__name__)


from ndg.security.server.attributeauthority.AttributeAuthority_services_server import \
	AttributeAuthorityService as _AttributeAuthorityService

from ndg.security.server.attributeauthority import AttributeAuthority, \
	AttributeAuthorityAccessDenied
	
from ndg.security.common.X509 import X509Cert, X509CertRead

from ndgsecurity.config.soap import SOAPMiddleware


class AttributeAuthorityWS(_AttributeAuthorityService):

    def __init__(self):
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
        	import pdb
        	pdb.set_trace()
         
        # Initialize Attribute Authority class - property file will be
        # picked up from default location under $NDG_DIR directory
        self.aa = AttributeAuthority()


    def soap_getAttCert(self, ps, **kw):
        '''Retrieve an Attribute Certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _AttributeAuthorityService.soap_getAttCert(self, ps)

        # Derive designated holder cert differently according to whether
        # a signed message is expected from the client
        if self.aa.has_key('WS-Security'):
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            holderCert = WSSecurityHandler.signatureHandler.verifyingCert
        else:
            # No signature from client - they must instead provide the
            # designated holder cert via the UserX509Cert input
            holderCert = request.UserX509Cert

        try:	
        	attCert = self.aa.getAttCert(userId=request.UserId,
                                         holderCert=holderCert,
                                         userAttCert=request.UserAttCert)  
	        response.AttCert = attCert.toString()
	        
        except AttributeAuthorityAccessDenied, e:
            response.Msg = str(e)
			
        return request, response
       

    def soap_getHostInfo(self, ps, **kw):
        '''Get information about this host
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _AttributeAuthorityService.soap_getHostInfo(self, ps)
        
        response.Hostname = self.aa.hostInfo.keys()[0]
        response.AaURI = self.aa.hostInfo[response.Hostname]['aaURI']
        response.AaDN = self.aa.hostInfo[response.Hostname]['aaDN']
        response.LoginURI = self.aa.hostInfo[response.Hostname]['loginURI']
        response.LoginServerDN = \
        	self.aa.hostInfo[response.Hostname]['loginServerDN']
        response.LoginRequestServerDN = \
        	self.aa.hostInfo[response.Hostname]['loginRequestServerDN']

        return request, response
       

    def soap_getAllHostsInfo(self, ps, **kw):
        '''Get information about all hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _AttributeAuthorityService.soap_getAllHostsInfo(self, ps)
        

        trustedHostInfo = self.aa.getTrustedHostInfo()

		# Convert ready for serialization
		
		# First get info for THIS Attribute Authority ...
		# Nb. No role lsit applies here
        hosts = [response.new_hosts()]
        
        hosts[0].Hostname = self.aa.hostInfo.keys()[0]
        
        hosts[0].AaURI = \
        	self.aa.hostInfo[hosts[0].Hostname]['aaURI']
        hosts[0].AaDN = \
        	self.aa.hostInfo[hosts[0].Hostname]['aaDN']

        hosts[0].LoginURI = self.aa.hostInfo[hosts[0].Hostname]['loginURI']
        hosts[0].LoginServerDN = \
        	self.aa.hostInfo[hosts[0].Hostname]['loginServerDN']
        hosts[0].LoginRequestServerDN = \
        	self.aa.hostInfo[hosts[0].Hostname]['loginRequestServerDN']
        
		# ... then append info for other trusted attribute authorities...
        for hostname, hostInfo in trustedHostInfo.items():
            host = response.new_hosts()
			
            host.Hostname = hostname
            host.AaURI = hostInfo['aaURI']
            host.AaDN = hostInfo['aaDN']
            host.LoginURI = hostInfo['loginURI']
            host.LoginServerDN = hostInfo['loginServerDN']
            host.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            host.RoleList = hostInfo['role']
			
            hosts.append(host)
			
        response.Hosts = hosts

        return request, response


    def soap_getTrustedHostInfo(self, ps, **kw):
        '''Get information about other trusted hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = \
                    	_AttributeAuthorityService.soap_getTrustedHostInfo(self, ps)
        
        trustedHostInfo = self.aa.getTrustedHostInfo(role=request.Role)

		# Convert ready for serialization
        trustedHosts = []
        for hostname, hostInfo in trustedHostInfo.items():
            trustedHost = response.new_trustedHosts()
			
            trustedHost.Hostname = hostname
            trustedHost.AaURI = hostInfo['aaURI']
            trustedHost.AaDN = hostInfo['aaDN']
            trustedHost.LoginURI = hostInfo['loginURI']
            trustedHost.LoginServerDN = hostInfo['loginServerDN']
            trustedHost.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            trustedHost.RoleList = hostInfo['role']
			
            trustedHosts.append(trustedHost)
			
        response.TrustedHosts = trustedHosts
		
        return request, response


    def soap_getX509Cert(self, ps, **kw):
    	'''Retrieve Attribute Authority's X.509 certificate
    	
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _AttributeAuthorityService.soap_getX509Cert(self, ps)
        
        x509Cert = X509CertRead(self.aa['signingCertFilePath'])
        response.X509Cert = base64.encodestring(x509Cert.asDER())
        return request, response
