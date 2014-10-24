"""WSGI Middleware components - OpenID Provider package Attribute Exchange
Interface plugins sub-package

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "27/03/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from ndg.security.server.wsgi.openid.provider import IdentityMapping

class AXInterfaceError(Exception):
    """Base class for Attribute Exchange Interface Errors"""

class AXInterfaceConfigError(AXInterfaceError):
    """Attribute Exchange Interface configuration error"""

class MissingRequiredAttrs(AXInterfaceError):
    """Raised by the AXInterface __call__ method if the Relying Party has 
    requested attributes that this OpenID Provider cannot or is unable to 
    release"""

class AXInterfaceRetrieveError(AXInterfaceError):
    """Error retrieving attributes from use repository"""
    
class AXInterfaceReloginRequired(AXInterfaceError):
    """Raise from AXInterface.__call__ if re-login is required"""
    
class AXInterface(object):
    """Interface class for OpenID Provider to respond to Attribute Exchange
    Requests from a Relying Party"""
    __slots__ = ()
    
    userIdentifier2IdentityURI = IdentityMapping.userIdentifier2IdentityURI
    identityUri2UserIdentifier = IdentityMapping.identityUri2UserIdentifier
     
    def __init__(self, **cfg):
        """Add custom settings from the OpenID Provider's 
        openid.provider.axResponse.* settings contained in the host 
        Paste ini file
        
        @type cfg: dict
        @param cfg: dictionary of configuration parameters read in from 
        openid.provider.axinterface.* config settings.
        @raise AXInterfaceConfigError: if settings are missing or incorrect"""
        raise NotImplementedError()
    
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
        @param authnInterface: custom authentication interface set
        at login.  See 
        ndg.security.server.openid.provider.AbstractAuthNInterface for more 
        information
        @type authnCtx: dict like
        @param authnCtx: session containing authentication context information
        such as username and OpenID user identifier URI snippet
        """
        raise NotImplementedError()