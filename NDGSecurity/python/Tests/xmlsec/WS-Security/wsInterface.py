"""WS-Security test SOAP interface definitions

NERC Data Grid Project

P J Kershaw 01/09/06

Copyright (C) 2009 Science and Technology Facilities Council

"""

__revision__ = '$Id$'

import ZSI
from ZSI import dispatch, TCcompound, TC
from ZSI.TC import TypeDefinition, ElementDeclaration
from ZSI.generate.pyclass import pyclass_type


class echoRequest(TCcompound.Struct): 
    def __init__(self, name=None, ns=None):
        self._message = None

        oname = None
        if name:
            oname = name
            if ns:
                oname += ' xmlns="%s"' % ns
            TC.Struct.__init__(self, 
                               echoRequest, 
                               [TC.String(pname="message",
                                          aname="_message",
                                          optional=1),], 
                               pname=name, 
                               aname="_%s" % name, 
                               oname=oname)

            
class echoRequestWrapper(echoRequest):
    """wrapper for message"""

    typecode = echoRequest(name='echo', ns='urn:echoServer')
    
    def __init__( self, name=None, ns=None, **kw ):
        echoRequest.__init__(self, name='echo', ns='urn:echoServer')

        
class echoResponse(TCcompound.Struct): 
    def __init__(self, name=None, ns=None):
        self._message = None

        oname = None
        if name:
            oname = name
            if ns:
                oname += ' xmlns="%s"' % ns
            TC.Struct.__init__(self, 
                               echoResponse, 
                               [TC.String(pname="message",
                                          aname="_message",
                                          optional=1),], 
                               pname=name, 
                               aname="_%s" % name, 
                               oname=oname)

            
class echoResponseWrapper(echoResponse):
    """wrapper for message"""

    typecode = echoResponse(name='echoResponse', ns='urn:echoServer')
    
    def __init__( self, name=None, ns=None, **kw ):
        echoResponse.__init__(self, name='echoResponse', ns='urn:echoServer')
