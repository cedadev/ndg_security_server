#!/usr/bin/env python
"""MyProxy Client interface

Based on original program myproxy_logon Tom Uram <turam@mcs.anl.gov>

NERC Data Grid Project

@author P J Kershaw 05/12/06

@copyright (C) 2009 Science and Technology Facilities Council

@license This software may be distributed under the terms of the Q Public 
License, version 1.0 or later.
"""

import os
import socket
from M2Crypto import X509, RSA, EVP, m2, BIO
from M2Crypto.SSL.Context import Context
from M2Crypto.SSL.Connection import Connection

import re
import base64


class MyProxyClientError(Exception):
    """Catch all exception class"""
    
class GetError(Exception):
    """Exceptions arising from get request to server"""
    
class RetrieveError(Exception):
    """Error recovering a response from MyProxy"""


class MyProxyClient(object):
    """MyProxy client interface 
    
    Based on protocol definitions in: 
    
    http://grid.ncsa.uiuc.edu/myproxy/protocol/
    
    @cvar __getCmd: get command string
    @cvar __storeCmd: store command string
    @cvar _certReqParamName: names of parameters needed to generate a 
    certificate request e.g. CN, OU etc.
    """
      
    __getCmd="""VERSION=MYPROXYv2
COMMAND=0
USERNAME=%s
PASSPHRASE=%s
LIFETIME=%d\0"""
 
    __infoCmd="""VERSION=MYPROXYv2
COMMAND=2
USERNAME=%s
PASSPHRASE=PASSPHRASE
LIFETIME=0"""
 
    __destroyCmd="""VERSION=MYPROXYv2
COMMAND=3
USERNAME=%s
PASSPHRASE=PASSPHRASE
LIFETIME=0"""

    __changePassphraseCmd="""VERSION=MYPROXYv2
 COMMAND=4
 USERNAME=%s
 PASSPHRASE=%s
 NEW_PHRASE=%s
 LIFETIME=0"""
   
    __storeCmd="""VERSION=MYPROXYv2
COMMAND=5
USERNAME=%s
PASSPHRASE=
LIFETIME=%d\0"""

 
    _certReqParamName = ('O', 'OU')

    #_________________________________________________________________________            
    def __init__(self, 
                 hostname=os.environ.get('MYPROXY_SERVER'), 
                 port=7512,
                 **certReqKw):
        """
        @param hostname string for MyProxy server - defaults to 
        MYPROXY_SERVER environment variable
        @param integer port number MyProxy is running on
        """
        self.hostname = hostname
        self.port = port
        
        # Set-up parameter names for certificate request
        self.__certReqParam = {}.fromkeys(MyProxyClient._certReqParamName)
        
        # Check for parameter names set from input
        self.certReqParam = certReqKw

    #_________________________________________________________________________        
    def __setCertReqParam(self, dict):
        '''certReqParam property set method - forces setting of certificate 
        request parameter names to valid values
        
        @param dict: dictionary of parameters'''
        
        invalidKw = [k for k in dict \
                     if k not in MyProxyClient._certReqParamName]
        if invalidKw:
            raise MyProxyClientError, \
    "Invalid certificate request keyword(s): %s.  Valid keywords are: %s" % \
    (', '.join(invalidKw), ', '.join(MyProxyClient._certReqParamName))
    
        self.__certReqParam.update(dict)

    #_________________________________________________________________________        
    def __getCertReqParam(self):
        """certReqParam property set method - for Certificate request 
        parameters dict"""
        return self.__certReqParam
    
    
    certReqParam = property(fset=__setCertReqParam,
                            fget=__getCertReqParam,
                            doc="Dictionary of parameters for cert. request")
    
    #_________________________________________________________________________        
    def _createCertReq(self, CN, nBitsForKey=1024, messageDigest="md5"):
        """
        Create a certificate request.
        
        @param CN: Common Name for certificate - effectively the same as the
        username for the MyProxy credential
        @param nBitsForKey: number of bits for private key generation - 
        default is 1024
        @param messageDigest: message disgest type - default is MD5
        @return tuple of certificate request PEM text and private key PEM text
        """
        
        # Check all required certifcate request DN parameters are set                
        # Create certificate request
        req = X509.Request()
    
        # Generate keys
        key = RSA.gen_key(nBitsForKey, m2.RSA_F4)
    
        # Create public key object
        pubKey = EVP.PKey()
        pubKey.assign_rsa(key)
        
        # Add the public key to the request
        req.set_version(0)
        req.set_pubkey(pubKey)
        
        # Set DN
        x509Name = X509.X509_Name()
        x509Name.CN = CN
        x509Name.OU = self.__certReqParam['OU']
        x509Name.O = self.__certReqParam['O']
        req.set_subject_name(x509Name)
        
        req.sign(pubKey, messageDigest)
        
        return (req.as_asn1(), key.as_pem(cipher=None))
    
    
    #_________________________________________________________________________           
    def _deserializeResponse(self, msg, *fieldNames):
        """
        Deserialize a MyProxy server response
        
        @param msg: string response message from MyProxy server
        @*fieldNames: the content of additional fields can be returned by 
        specifying the field name or names as additional arguments e.g. info
        method passes 'CRED_START_TIME', 'CRED_END_TIME' and 'CRED_OWNER'
        field names.  The content of fields is returned as an extra element
        in the tuple response.  This element is itself a dictionary indexed
        by field name.
        @return tuple of integer response and errorTxt string (if any)
        """
        
        lines = msg.split('\n')
        
        # get response value
        responselines = filter(lambda x: x.startswith('RESPONSE'), lines)
        responseline = responselines[0]
        respCode = int(responseline.split('=')[1])
        
        # get error text
        errorTxt = ""
        errorlines = filter(lambda x: x.startswith('ERROR'), lines)
        for e in errorlines:
            etext = e.split('=', 1)[1]
            errorTxt += etext
        
        if fieldNames:
            fields = {}
                        
            for fieldName in fieldNames:
                fieldlines = filter(lambda x: x.startswith(fieldName), lines)
                try:
                    # Nb. '1' arg to split ensures owner DN is not split up.
                    field = fieldlines[0].split('=', 1)[1]
                    fields[fieldName]=field.isdigit() and int(field) or field

                except IndexError:
                    # Ignore fields that aren't found
                    pass
                
            return respCode, errorTxt, fields
        else:
            return respCode, errorTxt
    
  
    #_________________________________________________________________________             
    def _deserializeCerts(self, inputDat):
        """Unpack certificates returned from a get delegation call to the
        server
        
        @param inputDat: string containing the proxy cert and private key
        and signing cert all in DER format
        
        @return list containing the equivalent to the input in PEM format"""
        pemCerts = []        
        dat = inputDat
        
        while dat:    
            # find start of cert, get length        
            ind = dat.find('\x30\x82')
            if ind < 0:
                break
                
            len = 256*ord(dat[ind+2]) + ord(dat[ind+3])
    
            # extract der-format cert, and convert to pem
            derCert = dat[ind:ind+len+4]
            
            x509 = X509.load_cert_string(derCert, type=X509.TYPE_ASN1)
            pemCert = x509.as_pem()
            
            pemCerts.append(pemCert)
    
            # trim cert from data
            dat = dat[ind + len + 4:]
           
        return pemCerts


    #_________________________________________________________________________   
    def info(self,
             username, 
             ownerCertFile=None,
             ownerKeyFile=None,
             ownerPassphrase=None):
        """return True/False whether credentials exist on the server for a 
        given username
        
        Exceptions:  GetError, StoreCredError
        
        @param username: username selected for credential
        @param ownerCertFile: certificate used for client authentication with
        the MyProxy server SSL connection.  This ID will be set as the owner
        of the stored credentials.  Only the owner can later remove 
        credentials with myproxy-destroy or the destroy method.  If not set,
        this argument defaults to $GLOBUS_LOCATION/etc/hostcert.pem 
        @param ownerKeyFile: corresponding private key file.  See explanation
        for ownerCertFile
        @param ownerPassphrase: passphrase for ownerKeyFile.  Omit if the
        private key is not password protected.  
        @return none
        """
        globusLoc = os.environ.get('GLOBUS_LOCATION')
        if not ownerCertFile or not ownerKeyFile:
            if globusLoc:
                ownerCertFile = os.path.join(globusLoc, 'etc', 'hostcert.pem')
                ownerKeyFile = os.path.join(globusLoc, 'etc', 'hostkey.pem')
            else:
                raise MyProxyClientError, \
            "No client authentication cert. and private key file were given"
        

        context = Context(protocol='sslv3')
        context.load_cert(ownerCertFile,
                          keyfile=ownerKeyFile,
                          callback=lambda *ar, **kw: ownerPassphrase)
    
        # Disable for compatibility with myproxy server (er, globus)
        # globus doesn't handle this case, apparently, and instead
        # chokes in proxy delegation code
        context.set_options(m2.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        
        # connect to myproxy server
        conn = Connection(context, sock=socket.socket())
        
        # Fudge to avoid checking client cert - seems to pick globus 
        # host/<hostname> one
        conn.clientPostConnectionCheck = None
        conn.connect((self.hostname, self.port))
        
        # send globus compatibility stuff
        conn.write('0')
    
        # send info command
        cmd = MyProxyClient.__infoCmd % username
        conn.write(cmd)
    
        # process server response
        dat = conn.recv(8192)
         
        # Pass in the names of fields to return in the dictionary 'field' 
        respCode, errorTxt, field = self._deserializeResponse(dat, 
                                                         'CRED_START_TIME', 
                                                         'CRED_END_TIME', 
                                                         'CRED_OWNER')

        return not bool(respCode), errorTxt, field


    #_________________________________________________________________________   
    def changePassphrase(self,
                         username, 
                         passphrase,
                         newPassphrase,
                         ownerCertFile=None,
                         ownerKeyFile=None,
                         ownerPassphrase=None):
        """change pass-phrase protecting the credentials for a given username
        
        Exceptions:  GetError, StoreCredError
        
        @param username: username of credential
        @param passphrase: existing pass-phrase for credential
        @param newPassphrase: new pass-phrase to replace the existing one.
        @param ownerCertFile: certificate used for client authentication with
        the MyProxy server SSL connection.  This ID will be set as the owner
        of the stored credentials.  Only the owner can later remove 
        credentials with myproxy-destroy or the destroy method.  If not set,
        this argument defaults to $GLOBUS_LOCATION/etc/hostcert.pem 
        @param ownerKeyFile: corresponding private key file.  See explanation
        for ownerCertFile
        @param ownerPassphrase: passphrase for ownerKeyFile.  Omit if the
        private key is not password protected.  
        @return none
        """
        globusLoc = os.environ.get('GLOBUS_LOCATION')
        if not ownerCertFile or not ownerKeyFile:
            if globusLoc:
                ownerCertFile = os.path.join(globusLoc, 'etc', 'hostcert.pem')
                ownerKeyFile = os.path.join(globusLoc, 'etc', 'hostkey.pem')
            else:
                raise MyProxyClientError, \
            "No client authentication cert. and private key file were given"
        
        import pdb;pdb.set_trace()
        context = Context(protocol='sslv3')
        context.load_cert(ownerCertFile,
                          keyfile=ownerKeyFile,
                          callback=lambda *ar, **kw: ownerPassphrase)
    
        # Disable for compatibility with myproxy server (er, globus)
        # globus doesn't handle this case, apparently, and instead
        # chokes in proxy delegation code
        context.set_options(m2.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        
        # connect to myproxy server
        conn = Connection(context, sock=socket.socket())
        
        # Fudge to avoid checking client cert - seems to pick globus 
        # host/<hostname> one
        conn.clientPostConnectionCheck = None
        conn.connect((self.hostname, self.port))
        
        # send globus compatibility stuff
        conn.write('0')
    
        # send command
        cmd = MyProxyClient.__changePassphraseCmd % (username, 
                                                     passphrase,
                                                     newPassphrase)
        conn.write(cmd)
    
        # process server response
        dat = conn.recv(8192)
            
        respCode, errorTxt = self._deserializeResponse(dat)
        if respCode:
            raise GetError, errorTxt


    #_________________________________________________________________________   
    def destroy(self,
                username, 
                ownerCertFile=None,
                ownerKeyFile=None,
                ownerPassphrase=None):
        """destroy credentials from the server for a given username
        
        Exceptions:  GetError, StoreCredError
        
        @param username: username selected for credential
        @param ownerCertFile: certificate used for client authentication with
        the MyProxy server SSL connection.  This ID will be set as the owner
        of the stored credentials.  Only the owner can later remove 
        credentials with myproxy-destroy or the destroy method.  If not set,
        this argument defaults to $GLOBUS_LOCATION/etc/hostcert.pem 
        @param ownerKeyFile: corresponding private key file.  See explanation
        for ownerCertFile
        @param ownerPassphrase: passphrase for ownerKeyFile.  Omit if the
        private key is not password protected.  
        @return none
        """
        globusLoc = os.environ.get('GLOBUS_LOCATION')
        if not ownerCertFile or not ownerKeyFile:
            if globusLoc:
                ownerCertFile = os.path.join(globusLoc, 'etc', 'hostcert.pem')
                ownerKeyFile = os.path.join(globusLoc, 'etc', 'hostkey.pem')
            else:
                raise MyProxyClientError, \
            "No client authentication cert. and private key file were given"
        

        context = Context(protocol='sslv3')
        context.load_cert(ownerCertFile,
                          keyfile=ownerKeyFile,
                          callback=lambda *ar, **kw: ownerPassphrase)
    
        # Disable for compatibility with myproxy server (er, globus)
        # globus doesn't handle this case, apparently, and instead
        # chokes in proxy delegation code
        context.set_options(m2.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        
        # connect to myproxy server
        conn = Connection(context, sock=socket.socket())
        
        # Fudge to avoid checking client cert - seems to pick globus 
        # host/<hostname> one
        conn.clientPostConnectionCheck = None
        conn.connect((self.hostname, self.port))
        
        # send globus compatibility stuff
        conn.write('0')
    
        # send destroy command
        cmd = MyProxyClient.__destroyCmd % username
        conn.write(cmd)
    
        # process server response
        dat = conn.recv(8192)
            
        respCode, errorTxt = self._deserializeResponse(dat)
        if respCode:
            raise GetError, errorTxt


    #_________________________________________________________________________   
    def store(self,
              username, 
              certFile,
              keyFile,
              ownerCertFile=None,
              ownerKeyFile=None,
              ownerPassphrase=None,
              lifetime=43200):
        """Upload credentials to the server
        
        Exceptions:  GetError, StoreCredError
        
        @param username: username selected for credential
        @param certFile: user's X.509 certificate in PEM format
        @param keyFile: equivalent private key file in PEM format
        @param ownerCertFile: certificate used for client authentication with
        the MyProxy server SSL connection.  This ID will be set as the owner
        of the stored credentials.  Only the owner can later remove 
        credentials with myproxy-destroy or the destroy method.  If not set,
        this argument defaults to $GLOBUS_LOCATION/etc/hostcert.pem or if this
        is not set, certFile
        @param ownerKeyFile: corresponding private key file.  See explanation
        for ownerCertFile
        @param ownerPassphrase: passphrase for ownerKeyFile.  Omit if the
        private key is not password protected.  Nb. keyFile is expected to
        be passphrase protected as this will be the passphrase used for
        logon / getDelegation.
        @return none
        """
        globusLoc = os.environ.get('GLOBUS_LOCATION')
        if not ownerCertFile or not ownerKeyFile:
            if globusLoc:
                ownerCertFile = os.path.join(globusLoc, 'etc', 'hostcert.pem')
                ownerKeyFile = os.path.join(globusLoc, 'etc', 'hostkey.pem')
            else:
                ownerCertFile = certFile 
                ownerKeyFile = keyFile
        

        context = Context(protocol='sslv3')
        context.load_cert(ownerCertFile,
                          keyfile=ownerKeyFile,
                          callback=lambda *ar, **kw: ownerPassphrase)
#        context.load_cert('../hostcert.pem',
#                          keyfile='../hostkey.pem',
#                          callback=lambda *ar, **kw: ownerPassphrase)
    
        # Disable for compatibility with myproxy server (er, globus)
        # globus doesn't handle this case, apparently, and instead
        # chokes in proxy delegation code
        context.set_options(m2.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        
        # connect to myproxy server
        conn = Connection(context, sock=socket.socket())
        
        # Fudge to avoid checking client cert - seems to pick globus 
        # host/<hostname> one
        #conn.clientPostConnectionCheck = None
        conn.connect((self.hostname, self.port))
        
        # send globus compatibility stuff
        conn.write('0')
    
        # send store command
        cmd = MyProxyClient.__storeCmd % (username, lifetime)
        conn.write(cmd)
    
        # process server response
        dat = conn.recv(8192)
            
        respCode, errorTxt = self._deserializeResponse(dat)
        if respCode:
            raise GetError, errorTxt
        
        # Send certificate and private key
        certTxt = X509.load_cert(certFile).as_pem()
        keyTxt = open(keyFile).read()
        
        conn.send(certTxt + keyTxt)
    
    
        # process server response
        resp = conn.recv(8192)
        respCode, errorTxt = self._deserializeResponse(resp)
        if respCode:
            raise RetrieveError, errorTxt
        
    #_________________________________________________________________________           
    def logon(self, username, passphrase, lifetime=43200):
        """Retrieve a proxy credential from a MyProxy server
        
        Exceptions:  GetError, RetrieveError
        
        @param username: username of credential
        @param passphrase: pass-phrase for private key of credential held on
        server
        @return list containing the credentials as strings in PEM format: the
        proxy certificate, it's private key and the signing certificate.
        """
    
        context = Context(protocol='sslv3')
        
        # disable for compatibility with myproxy server (er, globus)
        # globus doesn't handle this case, apparently, and instead
        # chokes in proxy delegation code
        context.set_options(m2.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        
        # connect to myproxy server
        conn = Connection(context, sock=socket.socket())
        
        # Fudge to avoid checking client cert - seems to pick globus 
        # host/<hostname> one
        conn.clientPostConnectionCheck = None
        conn.connect((self.hostname, self.port))
        
        # send globus compatibility stuff
        conn.write('0')
    
        # send get command
        cmd = MyProxyClient.__getCmd % (username,passphrase,lifetime)
        conn.write(cmd)
    
        # process server response
        dat = conn.recv(8192)
        respCode, errorTxt = self._deserializeResponse(dat)
        if respCode:
            raise GetError, errorTxt
        
        # generate and send certificate request
        # - The client will generate a public/private key pair and send a 
        #   NULL-terminated PKCS#10 certificate request to the server.
        certReq, priKey = self._createCertReq(username)
        conn.send(certReq)
    
        # process certificates
        # - 1 byte , number of certs
        dat = conn.recv(1)
        nCerts = ord(dat[0])
        
        # - n certs
        dat = conn.recv(8192)
    
        # process server response
        resp = conn.recv(8192)
        respCode, errorTxt = self._deserializeResponse(resp)
        if respCode:
            raise RetrieveError, errorTxt
    
        # deserialize certs from received cert data
        pemCerts = self._deserializeCerts(dat)
        if len(pemCerts) != nCerts:
            RetrieveError, "%d certs expected, %d received" % \
                                                    (nCerts, len(pemCerts))
    
        # write certs and private key to file
        # - proxy cert
        # - private key
        # - rest of cert chain
        creds = pemCerts[0]+priKey+''.join([cert for cert in pemCerts[1:]])
        
        return creds
        

    def getDelegation(self, *arg, **kw):
        """Retrieve proxy cert for user - same as logon"""
        self.logon(*arg, **kw)


#_____________________________________________________________________________   
def main():
    import sys
    import optparse
    import getpass
    
    parser = optparse.OptionParser()
    parser.add_option("-i", 
                      "--info", 
                      dest="info", 
                      default=False,
                      action="store_true",
                      help="check whether a credential exists")

    parser.add_option("-z", 
                      "--destroy", 
                      dest="destroy", 
                      default=False,
                      action="store_true",
                      help="destroy credential")

    parser.add_option("-C", 
                      "--change-pass-phrase", 
                      dest="changePassphrase", 
                      default=False,
                      action="store_true",
                      help="change pass-phrase protecting credential")

    parser.add_option("-g", 
                      "--get-delegation", 
                      dest="getDelegation", 
                      default=False,
                      action="store_true",
                      help="Get delegation / logon")
    
    parser.add_option("-c", 
                      "--certfile", 
                      dest="certFile", 
                      default=None,
                      help="Certificate to be stored")
    
    parser.add_option("-y", 
                      "--keyfile", 
                      dest="keyFile", 
                      default=None,
                      help="Private key to be stored")
    
    parser.add_option("-w", 
                      "--keyfile-passphrase", 
                      dest="ownerPassphrase", 
                      default=None,
                      help="Pass-phrase for Private key used for SSL client")

    parser.add_option("-s", 
                      "--pshost", 
                      dest="host", 
                      help="The hostname of the MyProxy server to contact")
    
    parser.add_option("-p", 
                      "--psport", 
                      dest="port", 
                      default=7512,
                      type="int",
                      help="The port of the MyProxy server to contact")
    
    parser.add_option("-l", 
                      "--username", 
                      dest="username", 
                      help=\
    "The username with which the credential is stored on the MyProxy server")

    parser.add_option("-o", 
                      "--out", 
                      dest="outfile", 
                      help=\
    "The username with which the credential is stored on the MyProxy server")

    parser.add_option("-t", 
                      "--proxy-lifetime", 
                      dest="lifetime", 
                      default=43200,
                      type="int",
                      help=\
    "The username with which the credential is stored on the MyProxy server")

    (options, args) = parser.parse_args()
    

    # process options    
    username = options.username
    if not username:
        if sys.platform == 'win32':
            username = os.environ["USERNAME"]
        else:
            import pwd
            username = pwd.getpwuid(os.geteuid())[0]

    hostname = options.host or os.environ.get('MYPROXY_SERVER')
    myProxy = MyProxyClient(hostname=hostname,
                            port=options.port,
                            O='NDG',
                            OU='BADC')
    
    if options.getDelegation:
                
        outfile = options.outfile
        if not outfile:
            if sys.platform == 'win32':
                outfile = 'proxy'
            elif sys.platform in ['linux2','darwin']:
                outfile = '/tmp/x509up_u%s' % (os.getuid())
    
        # Get MyProxy password
        passphrase = getpass.getpass()
            
        # Retrieve proxy cert
        try:
            creds = myProxy.logon(username, 
                                  passphrase, 
                                  lifetime=options.lifetime)
            open(outfile, 'w').write(creds)
            print "A proxy has been received for user %s in %s." % \
                (username, outfile)
            
        except Exception,e:
            print "Error:", e
            sys.exit(1)
            
    elif options.changePassphrase:
                
        # Get MyProxy password
        passphrase = getpass.getpass(\
                     prompt='Enter (current) MyProxy pass phrase: ')
        
        newPassphrase = getpass.getpass(\
                                 prompt='Enter new MyProxy pass phrase: ')
        
        if newPassphrase != getpass.getpass(\
                     prompt='Verifying - Enter new MyProxy pass phrase: '):
            raise Exception, "Pass-phrases entered don't match"
        
        
        # Retrieve proxy cert
        try:
            myProxy.changePassphrase(username,
                             passphrase,
                             newPassphrase, 
                             options.certFile,
                             options.keyFile,
                             ownerPassphrase=open('../tmp2').read().strip())            
        except Exception,e:
            print "Error:", e
            sys.exit(1)
                
    elif options.info:
        try:
            credExists, errorTxt, fields = myProxy.info(username, 
                             options.certFile,
                             options.keyFile,
                             ownerPassphrase=open('../tmp2').read().strip())
            if credExists:
                print "username: %s" % username
                print "owner: %s" % fields['CRED_OWNER']
                print "  time left: %d" % \
                        (fields['CRED_END_TIME'] - fields['CRED_START_TIME'])
            else:
                ownerCert = X509.load_cert(options.certFile)
                ownerCertDN = '/' + \
                    ownerCert.get_subject().as_text().replace(', ', '/')
                print "no credentials found for user %s, owner \"%s\"" % \
                    (username, ownerCertDN)

        except Exception, e:
            print "Error:", e
            sys.exit(1)
                
    elif options.destroy:
        try:
            myProxy.destroy(username, 
                            ownerCertFile=options.certFile,
                            ownerKeyFile=options.keyFile,
                            ownerPassphrase=open('../tmp2').read().strip())
           
        except Exception, e:
            print "Error:", e
            sys.exit(1)
    else:
        try:
            myProxy.store(username, 
                          options.certFile,
                          options.keyFile,
                          ownerCertFile=options.certFile,
                          ownerKeyFile=options.keyFile,
                          ownerPassphrase=open('../tmp2').read().strip(),
                          lifetime=options.lifetime)
           
        except Exception, e:
            print "Error:", e
            sys.exit(1)


if __name__ == '__main__':
    main()
    