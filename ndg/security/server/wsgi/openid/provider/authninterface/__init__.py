"""WSGI Middleware components - OpenID package Authentication Interface
plugins sub-package

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "05/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)


class AuthNInterfaceError(Exception):
    """Base class for AbstractAuthNInterface exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enables callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    userMsg = ("An internal error occurred during login,  Please contact your "
               "system administrator")
    errorMsg = "AuthNInterface error"
    
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = self.__class__.errorMsg
            
        log.error(msg)
        Exception.__init__(self, msg, **kw)
        
        
class AuthNInterfaceInvalidCredentials(AuthNInterfaceError):
    """User has provided incorrect username/password.  Raise from logon"""
    userMsg = ("Invalid username / password provided.  Please try again.  If "
               "the problem persists please contact your system "
               "administrator")
    errorMsg = "Invalid username/password provided"


class AuthNInterfaceUsername2IdentifierMismatch(AuthNInterfaceError): 
    """User has provided a username which doesn't match the identifier from
    the OpenID URL that they provided.  DOESN'T apply to ID Select mode where
    the user has given a generic URL for their OpenID Provider."""
    userMsg = ("Invalid username for the OpenID entered.  Please ensure you "
               "have the correct OpenID and username and try again.  If the "
               "problem persists contact your system administrator")
    errorMsg = "invalid username / OpenID identifier combination"
    
    
class AuthNInterfaceRetrieveError(AuthNInterfaceError):
    """Error with retrieval of information to authenticate user e.g. error with
    database look-up.  Raise from logon"""
    errorMsg = ("An error occurred retrieving information to check the login "
                "credentials")


class AuthNInterfaceInitError(AuthNInterfaceError):
    """Error with initialisation of AuthNInterface.  Raise from __init__"""
    errorMsg = "AuthNInterface initialisation error"
    
    
class AuthNInterfaceConfigError(AuthNInterfaceError):
    """Error with Authentication configuration.  Raise from __init__"""
    errorMsg = "AuthNInterface configuration error"
    
    
class AbstractAuthNInterface(object):
    '''OpenID Provider abstract base class for authentication configuration.
    Derive from this class to define the authentication interface for users
    logging into the OpenID Provider'''
    
    # Slot declaration here enables derived classes to use slots if they want to
    __slots__ = ()
    
    def __init__(self, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceInitError: error with initialisation
        @raise AuthNInterfaceConfigError: error with configuration
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
    
    def logon(self, environ, identityURI, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter
        
        @type identityURI: basestring
        @param identityURI: user's identity URL e.g. 
        'https://joebloggs.somewhere.ac.uk/'
        
        @type username: basestring
        @param username: user identifier for authentication
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        @raise AuthNInterfaceUsername2IdentifierMismatch: username doesn't 
        match the OpenID URL provided by the user.  (Doesn't apply to ID Select
        type requests).
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to authenticate user e.g. error with database look-up.
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
        raise NotImplementedError()
    
    def username2UserIdentifiers(self, environ, username):
        """Map the login username to an identifier which will become the
        unique path suffix to the user's OpenID identifier.  The 
        OpenIDProviderMiddleware takes self.urls['id_url']/
        self.urls['id_yadis'] and adds it to this identifier:
        
            identifier = self._authN.username2UserIdentifiers(environ,
                                                              username)
            identityURL = self.createIdentityURI(self.urls['url_id'],
                                                 identifier)
        
        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type username: basestring
        @param username: user identifier
        
        @rtype: tuple
        @return: one or more identifiers to be used to make OpenID user 
        identity URL(s).
        
        @raise AuthNInterfaceConfigError: problem with the configuration 
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to identifier e.g. error with database look-up.
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
        raise NotImplementedError()

    def logout(self, authNInterface):
        """Stub to enable custom actions for logout.
        
        @type authNInterface: AbstractAuthNInterface derived type
        @param authNInterface: authentication interface object.  See
        AbstractAuthNInterface class for details
        """
        raise NotImplementedError()