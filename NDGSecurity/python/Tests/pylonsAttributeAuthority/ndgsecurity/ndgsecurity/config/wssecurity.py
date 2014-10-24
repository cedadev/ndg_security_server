import logging
log = logging.getLogger(__name__)

from ZSI.parse import ParsedSoap

from ZSI.writer import SoapWriter
from ndg.security.common.wssecurity.signaturehandler.dom import SignatureHandler

class SignatureMiddleware(object):
    '''Apply WS-Security digital signature to SOAP message'''
    
    def __init__(self, app, app_conf):
        self.app = app
        self.signatureHandler = SignatureHandler(
                                        cfg=app_conf.get('wsseCfgFilePath'))
    
    def __call__(self, environ, start_response):
        
        log.debug('Signing outbound message ...')
        app = self.app(environ, start_response)

        if 'ZSI.writer.SoapWriter' not in environ:
            raise KeyError("Expecting 'ZSI.writer.SoapWriter' key in environ")
        
        sw = environ['ZSI.writer.SoapWriter']
        self.signatureHandler.sign(sw)
        soapOut = str(sw)
        
        return [soapOut]
    

class SignatureVerificationMiddleware(object):
    '''Verify WS-Security digital signature in SOAP message'''
    
    def __init__(self, app, app_conf):
        log.debug("SignatureVerificationMiddleware.__init__ ...")
        self.app = app
        self.signatureHandler = SignatureHandler(
                                        cfg=app_conf.get('wsseCfgFilePath'))
    
    def __call__(self, environ, start_response):

        log.debug("Verifying inbound message signature...")
       
        # TODO: allow for chunked data
        soapIn = environ['wsgi.input'].read(environ['CONTENT_LENGTH'])
        
        ps = ParsedSoap(soapIn)
        self.signatureHandler.verify(ps)
        
        # Pass on in environment as an efficiency measure for any following
        # SOAP Middleware
        environ['ZSI.parse.ParsedSoap'] = ps
        return self.app(environ, start_response)


def makeSignatureVerificationFilter(app, global_conf):
    return SignatureVerificationMiddleware(app, global_conf) 

def makeSignatureFilter(app, global_conf):
    return SignatureMiddleware(app, global_conf)