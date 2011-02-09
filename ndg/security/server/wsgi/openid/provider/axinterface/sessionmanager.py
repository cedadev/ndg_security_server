"""NDG Security OpenID Provider AX Interface for Session Manager based 
authentication

This enables an OpenID Provider's to return a URI for the associated Session
Manager

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/03/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
from string import Template
from sqlalchemy import create_engine

from ndg.security.server.wsgi.openid.provider.axinterface import \
    AXInterface, AXInterfaceConfigError, MissingRequiredAttrs
from ndg.security.server.wsgi.openid.provider import AbstractAuthNInterface    
    
class SessionManagerAXInterface(AXInterface):
    '''Authentication interface class for OpenIDProviderMiddleware to enable
    authentication to a Session Manager instance running in the same WSGI
    stack or via a SOAP call to a remote service
    
    @type uriKeyName: basestring
    @cvar uriKeyName: expected key name in config for Session Manager
    endpoint'''
    
    propertyNames = (
        'sessionManagerURI', 
        'sessionManagerURITypeURI',
        'sessionIdTypeURI'
    )
    
    def __init__(self, **cfg):
        """Copy session manager URI setting from the input config dict
        
        @type **cfg: dict
        @param **cfg: dict containing the Session Manager URI setting
        @raise AuthNInterfaceConfigError: error with configuration
        """
        for name in SessionManagerAXInterface.propertyNames:
            val = cfg.get(name)
            if val is None:
                raise AXInterfaceConfigError("Missing configuration setting: "
                                             '"%s"' % name)   
                   
            setattr(self, name, val)
        
    def __call__(self, ax_req, ax_resp, authnInterface, authnCtx):
        """Add the attributes to the ax_resp object requested in the ax_req
        object.  If it is not possible to return them, raise 
        MissingRequiredAttrs error
        
        @type ax_req: openid.extensions.ax.FetchRequest
        @param ax_req: attribute exchange request object.  To find out what 
        attributes the Relying Party has requested for example, call
        ax_req.getRequiredAttrs()
        @type ax_resp: openid.extensions.ax.FetchResponse
        @param ax_resp: attribute exchange response object.  This method should
        update the settings in this object.  Use addValue and setValues methods
        @type authnInterface: AbstractAuthNInterface
        @param authnInterface: custom authentication context information set
        at login.  See 
        ndg.security.server.openid.provider.AbstractAuthNInterface for more
        information
        @type authnCtx: dict like
        @param authnCtx: session containing authentication context information
        such as username and OpenID user identifier URI snippet
        """
        reqAttrURIs = ax_req.getRequiredAttrs()
        if self.sessionManagerURITypeURI in reqAttrURIs:
            log.debug("Adding AX parameter %s=%s ...", 
                      self.sessionManagerURITypeURI,
                      self.sessionManagerURI)
            
            ax_resp.addValue(self.sessionManagerURITypeURI,
                             self.sessionManagerURI)
            
        if self.sessionIdTypeURI in reqAttrURIs:
            if not isinstance(authnInterface, AbstractAuthNInterface):
                raise AXInterfaceConfigError("Expecting "
                                             "AbstractAuthNInterface derived "
                                             "type for authnInterface arg; "
                                             "got: %s" % 
                                            authnInterface.__class__.__name__)
                
            # Check for uninitialised session
            if not authnInterface.sessionId:
                raise MissingRequiredAttrs("The Session Manager session ID "
                                           "is not set to a valid session")
                
            # TODO: Check for a stale session ID - would require config params
            # to set-up a Session Manager client
                
            log.debug("Adding AX parameter %s=%s ...", self.sessionIdTypeURI,
                                                    authnInterface.sessionId)
            
            ax_resp.addValue(self.sessionIdTypeURI, authnInterface.sessionId)