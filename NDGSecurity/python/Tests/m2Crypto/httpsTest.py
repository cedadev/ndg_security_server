#!/usr/bin/env python
from M2Crypto.httpslib import HTTPSConnection
from M2Crypto import SSL

hostname = 'ceda.ac.uk'
path = '/AttributeAuthority'
caDir = '/etc/grid-security/certificates'
#body = '''<SOAP-ENV:Envelope 
#xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" 
#xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
#xmlns:ns1="urn:ndg.security.sessionMgr">
#<SOAP-ENV:Header></SOAP-ENV:Header>
#<SOAP-ENV:Body><ns1:getAttCert/></SOAP-ENV:Body>'''
body = '''<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/">
    <soap11:Header></soap11:Header>
    <soap11:Body>
        <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" IssueInstant="2010-10-22T10:32:07.585451Z" ID="bf152f2e-d00f-44a3-93ea-968445bbeb4a">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">/O=STFC/OU=BADC/CN=Test</saml:Issuer>
            <saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml:NameID Format="urn:esg:openid">https://ceda.ac.uk/openid/Philip.Kershaw</saml:NameID>
            </saml:Subject>
            <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="GroupRole" Name="urn:esg:group:role" NameFormat="groupRole"></saml:Attribute>
            <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string"></saml:Attribute>
            <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="EmailAddress" Name="urn:esg:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string"></saml:Attribute>
            <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string"></saml:Attribute>
        </samlp:AttributeQuery>
    </soap11:Body>
</soap11:Envelope>
'''
ctx = SSL.Context()
ctx.load_verify_locations(capath=caDir)
ctx.set_verify(SSL.verify_peer, 9)
con = HTTPSConnection(hostname, ssl_context=ctx)
con.putrequest('POST', path)
con.putheader('Content-Type', 'text/xml')
con.putheader('Content-Length', str(len(body)))
con.endheaders()
con.send(body)
resp = con.getresponse()
print resp.read()

#con = HTTPSConnection(hostname)
#con.putrequest('GET', path)
#con.endheaders()
#resp = con.getresponse()
#print resp.read()
