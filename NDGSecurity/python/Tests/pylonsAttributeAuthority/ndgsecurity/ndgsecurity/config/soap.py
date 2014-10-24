"""NDG Security SOAP Service Middleware

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "27/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ZSI import EvaluateException, ParseException
from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ZSI import fault

from ZSI.ServiceContainer import ServiceSOAPBinding

class SOAPMiddleware(object):
       
    def __init__(self, app, app_conf, **kw):
        log.debug("SOAPMiddleware.__init__ ...")
        self.app = app
        
        self.app_conf = app_conf
        self.app_conf.update(kw)
        
        if 'ServiceSOAPBinding' not in self.app_conf:
            self.app_conf['ServiceSOAPBinding'] = ServiceSOAPBinding
            
        if 'pathInfo' not in self.app_conf:
            self.app_conf['pathInfo'] = '/'
            
    def __call__(self, environ, start_response):
        log.debug("SOAPMiddleware.__call__")
        
        # Apply filter for calls
        if not environ['PATH_INFO'].startswith(self.app_conf['pathInfo']):
            return self.app(environ, start_response)

        def start_response_wrapper(status, response_headers, exc_info=None):
            '''Ensure text/xml content type and set content length'''
            response_headers_alt=[(name,val) for name, val in response_headers\
                    if name.lower() not in ('content-type', 'content-length')]
            
            response_headers_alt += [('content-type', 'text/xml'),
                                ('content-length', "%d" % len(self.soapOut))]
                            
            return start_response(status, 
                                  response_headers_alt,
                                  exc_info)

        if 'ZSI.parse.ParsedSoap' in environ:
            ps = environ['ZSI.parse.ParsedSoap']
        else:
            # TODO: allow for chunked data
            soapIn = environ['wsgi.input'].read(environ['CONTENT_LENGTH'])
            log.debug("SOAP Request")
            log.debug("_"*80)
            log.debug(soapIn)
            log.debug("_"*80)
            
            ps = ParsedSoap(soapIn)
            
        method = getattr(self.app_conf['ServiceSOAPBinding'], 
                         'soap_%s' % environ['HTTP_SOAPACTION'].strip('"'))
        
        try:
            req, resp = method(ps)
        except Exception, e:
            self._writeFault(req, resp)
        
        sw = SoapWriter()
        sw.serialize(resp)
        
        # Make SoapWriter object available to any SOAP filters that follow
        environ['ZSI.writer.SoapWriter'] = sw
        self.soapOut = str(sw)
        
        log.debug("SOAP Response")
        log.debug("_"*80)
        log.debug(self.soapOut)
        log.debug("_"*80)
#                
#        if soap is not None:
#            return self._writeResponse(request, soap)
        
        app = self.app(environ, start_response_wrapper)
        #start_response("200 OK", [('Content-type', 'text/xml')])
        return [self.soapOut]


def makeFilter(app, app_conf):  
    from ndgsecurity.config.attributeauthority import AttributeAuthorityWS
    
    return SOAPMiddleware(app, app_conf,
                          ServiceSOAPBinding=AttributeAuthorityWS(),
                          pathInfo='/AttributeAuthority')