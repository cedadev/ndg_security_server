"""NDG Security Basic OpenID Authentication Interface.

A demonstration implementation of an authentication interface for 
OpenIDProviderMiddleware WSGI.  Username/password and OpenId user identifier
details are read from a config file and passed as keywords.  This class is not 
intended for production use.

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "01/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.security.server.wsgi.openid.provider.authninterface import \
    AbstractAuthNInterface, AuthNInterfaceInvalidCredentials, \
    AuthNInterfaceRetrieveError, AuthNInterfaceConfigError, \
    AuthNInterfaceUsername2IdentifierMismatch
 
    
class BasicAuthNInterface(AbstractAuthNInterface):
    '''Basic Authentication interface class for OpenIDProviderMiddleware 
    
    it uses username/password details retrieved from config file / keyword
    entry.  This class is for testing only.  NOT for production use'''
    
    IDENTITY_URI_TMPL_KEYNAME = 'identityUriTemplate'
    USERCREDS_PROPERTY_KEYNAME = 'userCreds'
    USERCREDS_KEYNAMES = ('password', 'identifiers')
    
    propertyKeyNames = (
        USERCREDS_PROPERTY_KEYNAME
    )
    
    getUserIdentifier = staticmethod(lambda identityURI: 
                                     identityURI.rsplit('/')[-1])
    
    def __init__(self, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceConfigError: error with configuration
        """
        # Test/Admin username/password set from ini/kw args
        self._identityUriTemplate = prop.get(
                                BasicAuthNInterface.IDENTITY_URI_TMPL_KEYNAME)
        userCredsField = prop.get(
                                BasicAuthNInterface.USERCREDS_PROPERTY_KEYNAME)
        if not userCredsField:
            raise AuthNInterfaceConfigError('No "%s" config option found' %
                                BasicAuthNInterface.USERCREDS_PROPERTY_KEYNAME)

        self._userCreds = {}
        for userEntry in userCredsField.split(): 
            # Split username, password and OpenID name list  
            userCreds = userEntry.strip().split(':')
            
            # Split OpenID name list
            userCreds[-1] = tuple(userCreds[-1].split(','))
            
            # Convert into a dictionary indexed by username
            userCredsKeys = BasicAuthNInterface.USERCREDS_KEYNAMES
            self._userCreds[userCreds[0]] = dict(list(zip(userCredsKeys, 
                                                     userCreds[1:])))  
    
    def logon(self, environ, identityURI, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type identityURI: basestring
        @param identityURI: user's identity URL e.g. 
        'https://joebloggs.somewhere.ac.uk/'

        @type username: basestring
        @param username: username
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        @raise AuthNInterfaceUsername2IdentifierMismatch: no OpenID matching
        the given username
        """
        if self._userCreds.get(username, {}).get('password') != password:
            raise AuthNInterfaceInvalidCredentials()
        
        # Assume identifier is at the end of the URI
        if identityURI is not None:
            userIdentifier = BasicAuthNInterface.getUserIdentifier(identityURI)
        
            if userIdentifier not in self._userCreds[username]['identifiers']:
                raise AuthNInterfaceUsername2IdentifierMismatch()

    def logout(self):
        pass
        
    def username2UserIdentifiers(self, environ, username):
        """Map the login username to an identifier which will become the
        unique path suffix to the user's OpenID identifier.  The 
        OpenIDProviderMiddleware takes self.urls['id_url'] and adds it to this
        identifier:
        
            identifier = self._authN.username2UserIdentifiers(environ,username)
            identityURL = self.urls['url_id'] + '/' + identifier
        
        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type username: basestring
        @param username: user identifier
        
        @rtype: tuple
        @return: identifiers to be used to make OpenID user identity URLs. 
        
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to identifier e.g. error with database look-up.
        """
        try:
            return self._userCreds[username]['identifiers']
        except KeyError:
            raise AuthNInterfaceRetrieveError('No entries for "%s" user' % 
                                              username)


from ndg.security.server.wsgi.utils.sessionmanagerclient import \
    WSGISessionManagerClient, AuthNServiceInvalidCredentials
    
class BasicSessionManagerOpenIDAuthNInterface(BasicAuthNInterface):
    '''Authentication interface class for OpenIDProviderMiddleware to enable
    authentication to a Session Manager instance running in the same WSGI
    stack or via a SOAP call to a remote service.  This is a basic test
    interface.  See sessionmanager module for a full implementation linking to
    a database via SQLAlchemy
    '''
    
    def __init__(self, **prop):
        """Extends BasicAuthNInterface initialising Session Manager Client
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceConfigError: error with configuration
        """
        user2Identifier = prop.pop('username2UserIdentifiers')
        if user2Identifier:
            self._username2Identifier = {}
            for i in user2Identifier.split():
                username, identifierStr = i.strip().split(':')
                identifiers = tuple(identifierStr.split(','))
                self._username2Identifier[username] = identifiers
        else:
            raise AuthNInterfaceConfigError('No "user2Identifier" config '
                                            'option found')

        self._client = WSGISessionManagerClient(**prop)
        
        # This is set at login
        self.sessionId = None
        
    def logon(self, environ, userIdentifier, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter
        
        @type username: basestring
        @param username: user identifier
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceUsername2IdentifierMismatch: no OpenID 
        identifiers match the given username
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        """        
        if userIdentifier is not None and \
           userIdentifier not in self._username2Identifier.get(username):
            raise AuthNInterfaceUsername2IdentifierMismatch()
        
        try:
            self._client.environ = environ
            connectResp = self._client.connect(username, passphrase=password)
            self.sessionId = connectResp[-1]
            log.debug("Connected to Session Manager with session ID: %s", 
                      self.sessionId)

        except AuthNServiceInvalidCredentials as e:
            log.exception(e)
            raise AuthNInterfaceInvalidCredentials()

    def logout(self):
        """logout from the Session Manager
        """
        try:
            self._client.disconnect(sessID=self.sessionId)
            
        except Exception as e:
            log.exception(e)
            raise AuthNInterfaceInvalidCredentials()
