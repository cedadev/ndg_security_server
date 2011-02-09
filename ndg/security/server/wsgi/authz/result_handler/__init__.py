"""WSGI Policy Enforcement Point basic result handler package - contains modules
with different result handler implementations.

Functionality in this module moved from original authz package location

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/01/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
from ndg.security.server.wsgi.session import (SessionMiddlewareBase, 
    SessionHandlerMiddlewareError, SessionHandlerMiddlewareConfigError)

class PEPResultHandlerMiddlewareError(SessionHandlerMiddlewareError):
    """Base exception for PEP Result Handler Middleware implementations"""
            
            
class PEPResultHandlerMiddlewareConfigError(SessionHandlerMiddlewareConfigError):
    """Configuration errors from PEP Result Handler Middleware implementations
    """
    
    
class PEPResultHandlerMiddlewareBase(SessionMiddlewareBase):
    """Abstract Base class for Policy Enforcement Point result handler 
    specialisations
    
    This class can be overridden to define custom behaviour for the access
    denied response e.g. include an interface to enable users to register for
    the dataset from which they have been denied access.  See 
    AuthorizationMiddlewareBase pepResultHandler keyword.
    
    Implementations of this class will be invoked if access is denied to a given
    resource.  An instance is incorporated into the call stack by passing it in 
    to a MultiHandler instance.  
    
    The MultiHandler is configured in the AuthorizationMiddlewareBase 
    class - see ndg.security.server.wsgi.authz.  The MultiHandler is passed a 
    checker method which determines whether to allow access, or call this 
    interface.   The checker is implemented in the PEPFilter.  See 
    ndg.security.server.wsgi.authz
    
    This class includes user session key and isAuthenticated property inherited 
    from SessionMiddlewareBase
    """
    
    @SessionMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Set access denied response in derived class
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """ 
        raise NotImplementedError()