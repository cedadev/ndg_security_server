#!/use/bin/env python
#from M2Crypto.httpslib import HTTPSConnection
from ndg.security.common.utils.m2crypto import HTTPSConnection

#hostname = u'ndgbeta.badc.rl.ac.uk'
hostname = u'gabriel.badc.rl.ac.uk'
path = u'/SessionManager'
#
#body = '''<SOAP-ENV:Envelope 
#xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" 
#xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
#xmlns:ns1="urn:ndg.security.sessionMgr">
#<SOAP-ENV:Header></SOAP-ENV:Header>
#<SOAP-ENV:Body><ns1:getAttCert/></SOAP-ENV:Body>'''

#con = HTTPSConnection(hostname)
#con.putrequest('POST', path)
#con.putheader('Content-Type', 'text/xml')
#con.putheader('Content-Length', str(len(body)))
#con.endheaders()
#con.send(body)
#resp = con.getresponse()
#print resp.read()

con = HTTPSConnection(hostname)
con.putrequest('GET', path)
con.endheaders()
resp = con.getresponse()
print resp.read()

#from httplib import HTTPConnection
#
#hostname = 'gabriel.badc.rl.ac.uk'
#port = 5000
#path = u'/AttributeAuthority'
#
#body = '''<SOAP-ENV:Envelope 
#xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" 
#xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
#xmlns:ns1="urn:ndg.security.attAuthority">
#<SOAP-ENV:Header></SOAP-ENV:Header>
#<SOAP-ENV:Body><ns1:getX509Cert/></SOAP-ENV:Body>'''
#
#con = HTTPConnection(hostname, port=5000)
#con.putrequest('POST', path)
#con.putheader('Content-Type', 'text/xml')
#con.putheader('Content-Length', str(len(body)))
#con.endheaders()
#con.send(body)
#resp = con.getresponse()
#print resp.read()



