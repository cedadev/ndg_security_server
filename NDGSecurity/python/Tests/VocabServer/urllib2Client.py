import urlparse, types
from ZSI.TCcompound import ComplexType, Struct
from ZSI import client
import ZSI

from ZSI import _copyright, _seqtypes, ParsedSoap, SoapWriter, TC, ZSI_SCHEMA_URI,\
    EvaluateException, FaultFromFaultMessage, _child_elements, _attrs,\
    _get_idstr, FaultException, WSActionException
from ZSI.auth import AUTH
from ZSI.TC import AnyElement, AnyType, String, TypeCode, _get_global_element_declaration,\
    _get_type_definition
import base64, httplib, Cookie, time
from ZSI.address import Address

import urllib, urllib2


class URLlib2Binding(client.Binding):
    def Send(self, url, opname, obj, nsdict={}, soapaction=None, wsaction=None, 
             endPointReference=None, **kw):
        '''Send a message.  If url is None, use the value from the
        constructor (else error). obj is the object (data) to send.
        Data may be described with a requesttypecode keyword, or a
        requestclass keyword; default is the class's typecode (if
        there is one), else Any.

        Optional WS-Address Keywords
            wsaction -- WS-Address Action, goes in SOAP Header.
            endPointReference --  set by calling party, must be an 
                EndPointReference type instance.

        '''
        url = url or self.url
        # Get the TC for the obj.
        if kw.has_key('requesttypecode'):
            tc = kw['requesttypecode']
        elif kw.has_key('requestclass'):
            tc = kw['requestclass'].typecode
        elif type(obj) == types.InstanceType:
            tc = getattr(obj.__class__, 'typecode')
            if tc is None: tc = TC.Any(opname, aslist=1)
        else:
            tc = TC.Any(opname, aslist=1)

        endPointReference = endPointReference or self.endPointReference

        # Serialize the object.
        d = {}

        d.update(self.nsdict)
        d.update(nsdict)

        useWSAddress = self.wsAddressURI is not None
        sw = SoapWriter(nsdict=d, header=True, outputclass=self.writerclass, 
                 encodingStyle=kw.get('encodingStyle'),)
        if kw.has_key('_args'):
            sw.serialize(kw['_args'], tc)
        else:
            sw.serialize(obj, tc)

        # Determine the SOAP auth element.  SOAP:Header element
        if self.auth_style & AUTH.zsibasic:
            sw.serialize_header(_AuthHeader(self.auth_user, self.auth_pass),
                _AuthHeader.typecode)

        # Serialize WS-Address
        if useWSAddress is True:
            if self.soapaction and wsaction.strip('\'"') != self.soapaction:
                raise WSActionException, 'soapAction(%s) and WS-Action(%s) must match'\
                    %(self.soapaction,wsaction)
            self.address = Address(url, self.wsAddressURI)
            self.address.setRequest(endPointReference, wsaction)
            self.address.serialize(sw)

        # WS-Security Signature Handler
        if self.sig_handler is not None:
            self.sig_handler.sign(sw)
        soapdata = str(sw)

        scheme,netloc,path,nil,nil,nil = urlparse.urlparse(url)

        # self.transport httplib.HTTPConnection derived class set-up removed
        # from HERE - this now handled by urllib2.urlopen()
        self.SendSOAPData(soapdata, url, soapaction, **kw)

    def SendSOAPData(self, soapdata, url, soapaction, headers={}, **kw):
        # Tracing?
        if self.trace:
            print >>self.trace, "_" * 33, time.ctime(time.time()), "REQUEST:"
            print >>self.trace, soapdata 
        
        # Create a request   
        req = urllib2.Request(url, data=soapdata)

        req.add_header("Content-length", "%d" % len(soapdata))
        req.add_header("Content-type", 'text/xml; charset=utf-8')
        
        # TODO: equivalent method for cookies using urllib2 
        #self.__addcookies()

        for header,value in headers.items():
            req.add_header(header, value)

        SOAPActionValue = '"%s"' % (soapaction or self.soapaction)
        req.add_header("SOAPAction", SOAPActionValue)
        
        # client.Binding has Authentication handler set-up code here - 
        # urllib2.HTTPBasicAuthHandler can do this instead?

        for header,value in self.user_headers:
            req.add_header(header, value)
        
        # Check for custom urllib2 handler class
        if 'urlHandler' in kw:
            if not isinstance(kw['urlHandler'], urllib2.BaseHandler):
                raise TypeError, \
            "URL Handler class %s must be derived from urllib2.BaseHandler" %\
                                    kw['urlHandler']
            
            # Make an opener and make it the default so that urllib2.urlopen
            # will use it
            urlOpener = urllib2.build_opener(kw['urlHandler'])
            urllib2.install_opener(urlOpener)
            
        # Send request [and receive response all in one (!) - implications
        # for client.Binding architecture + functionality??]
        self.response = urllib2.urlopen(req)
         
        # Clear prior receive state.
        self.data, self.ps = None, None
        
        
    def ReceiveRaw(self, **kw):
        '''Read a server reply, unconverted to any format and return it.
        '''
        if self.data: return self.data
        trace = self.trace
        
        if hasattr(self, 'response') and self.response is not None:
            self.reply_code, self.reply_msg, self.reply_headers, self.data = \
                self.response.code, self.response.msg, self.response.headers,\
                self.response.read()
           
            # Reset response for next call
            self.response = None
            if trace:
                print >>trace, "_" * 33, time.ctime(time.time()), "RESPONSE:"
                for i in (self.reply_code, self.reply_msg,):
                    print >>trace, str(i)
                print >>trace, "-------"
                print >>trace, str(self.reply_headers)
                print >>trace, self.data

            return self.data
        
        # else Send didn't use SendSOAPData...
        while 1:
            response = self.h.getresponse()
            self.reply_code, self.reply_msg, self.reply_headers, self.data = \
                response.status, response.reason, response.msg, response.read()
            if trace:
                print >>trace, "_" * 33, time.ctime(time.time()), "RESPONSE:"
                for i in (self.reply_code, self.reply_msg,):
                    print >>trace, str(i)
                print >>trace, "-------"
                print >>trace, str(self.reply_headers)
                print >>trace, self.data
            saved = None
            for d in response.msg.getallmatchingheaders('set-cookie'):
                if d[0] in [ ' ', '\t' ]:
                    saved += d.strip()
                else:
                    if saved: self.cookies.load(saved)
                    saved = d.strip()
            if saved: self.cookies.load(saved)
            if response.status == 401:
                if not callable(self.http_callbacks.get(response.status,None)):
                    raise RuntimeError, 'HTTP Digest Authorization Failed'
                self.http_callbacks[response.status](response)
                continue
            if response.status != 100: break

            # The httplib doesn't understand the HTTP continuation header.
            # Horrible internals hack to patch things up.
            self.h._HTTPConnection__state = httplib._CS_REQ_SENT
            self.h._HTTPConnection__response = None
        return self.data