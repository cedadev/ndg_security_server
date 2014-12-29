"""Extension to OpenID Provider Middleware to support HTTP Basic Auth interface

"""
__author__ = "P J Kershaw"
__date__ = "29/12/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import httplib
import traceback
import logging
log = logging.getLogger(__name__)
_debugLevel = log.getEffectiveLevel() <= logging.DEBUG

import paste.request
from paste.httpexceptions import HTTPUnauthorized

from ndg.security.server.wsgi.httpbasicauth import HttpBasicAuthMiddleware
from ndg.security.server.wsgi.openid.provider import (
                                        OpenIDProviderMiddleware,
                                        OpenIDProviderReloginRequired,
                                        OpenIDProviderMissingRequiredAXAttrs,
                                        OpenIDProviderMissingAXResponseHandler,
                                        AuthNInterfaceInvalidCredentials,
                                        AuthNInterfaceError)


class OpenIDProviderWithHttpBasicAuthMiddleware(OpenIDProviderMiddleware):
    '''OpenID Provider with support for HTTP Basic Auth'''
    
    @classmethod
    def app_factory(cls, app_conf, **local_conf):
        openidprovider_class = super(OpenIDProviderWithHttpBasicAuthMiddleware, 
                                     cls)
        openidprovider_app = openidprovider_class.app_factory(app_conf, 
                                                              **local_conf)

        # Wrap OpenID Provider to provide HTTP basic auth functionality
        basic_auth_filter = HttpBasicAuthMiddleware.filter_app_factory(
                                                    openidprovider_app, 
                                                    app_conf, **local_conf)
        
        # Set authentication callback for Basic Auth middleware so that it uses
        # the same authentication settings as the OpenID Provider
        basic_auth_filter.authentication_callback = \
                                    openidprovider_app.authentication_callback
                                    
        # Set intercept path for HTTP Basic Auth filter - it should correspond 
        # to the OpenID provider endpoint
        basic_auth_filter.re_path_match_list = (
                            openidprovider_app.paths['path_openidserver'], )
        
        return basic_auth_filter

    @property
    def authentication_callback(self):
        '''Return authentication callback function for use by HTTP Basic Auth
        middleware
        '''
        def authenticate(environ, start_response, username, password):
            '''Authentication callback for use with HTTP Basic Auth middleware.
            It applies the same authentication procedure as used with the 
            browser-based interface but tailored for scripted clients
            '''
            self._authenticate(environ, username, password)
            
            query_params = dict(paste.request.parse_formvars(environ))
            oid_request = self.oidserver.decodeRequest(query_params)
            
            identity_uri = self._resolve_and_validate_identity_uri(environ, 
                                                                   oid_request, 
                                                                   username)
            
            response = self._set_response(environ, start_response, oid_request,
                                          identity_uri)
            
            return response
                              
        return authenticate

    def _resolve_and_validate_identity_uri(self, environ, oid_request, 
                                           username):
        '''Get OpenID identity URI and check against credentials provided
        '''
        if oid_request.idSelect():
            # ID select mode enables the user to request specifying
            # their OpenID Provider without giving a personal user URL 
            try:
                user_identifiers = self._authN.username2UserIdentifiers(
                                                            environ, username)    
            except AuthNInterfaceInvalidCredentials:
                log.error("No username %r matching an OpenID URL: %s",
                          username, traceback.format_exc())
                raise

            if not isinstance(user_identifiers, (list, tuple)):
                raise TypeError("Unexpected type %r returned from %r for "
                                "user identifiers; expecting list or tuple" % 
                                (type(user_identifiers), type(self._authN)))
                
            # FIXME: Assume the *first* user identifier entry is the
            # one to use.  The user could have multiple identifiers
            # but in practice it's more manageable to have a single one
            identity_uri = self.createIdentityURI(self.identityUriTmpl,
                                                  user_identifiers[0])
        else:
            # Get the unique user identifier from the user's OpenID URL
            identity_uri = oid_request.identity
            
            # Check the username used to login with matches the identity URI 
            # given.  This check is essential otherwise a user could impersonate
            # someone else with an account with this provider
            try:
                user_identifiers = self._authN.username2UserIdentifiers(
                                                            environ, username)          
            except AuthNInterfaceInvalidCredentials:
                log.error("No username %r matching an OpenID URL: %s",
                          username, traceback.format_exc())
                raise
                
            expected_identity_uri = self.createIdentityURI(self.identityUriTmpl,
                                                           user_identifiers[0])
            if identity_uri != expected_identity_uri:
                log.error("OpenID given %r, doesn't match the expected "
                          "OpenID %r for this account name %r" % 
                          (identity_uri, expected_identity_uri, username))
                
                raise HTTPUnauthorized()
            
        return identity_uri

    def _authenticate(self, environ, username, password):
        session = environ.get(self.session_mware_environ_keyname, {})
        if (OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME in session):
            # user is already logged in
            return
        
        identity_uri = None
        
        if None in (username, password):
            raise HTTPUnauthorized()
        
        # Invoke custom authentication interface plugin
        try:
            self._authN.logon(environ, identity_uri, username, password)
            
        except AuthNInterfaceError, e:
            log.error("Authentication error: %s", traceback.format_exc())

            raise HTTPUnauthorized()
                           
        except Exception, e:
            log.error("Unexpected %s type exception raised during "
                      "authentication: %s", type(e),
                      traceback.format_exc())
            raise
        
        # Set user in environ
        environ['REMOTE_USER'] = username
        
        # Update session information
        session[OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME
                ] = username
        session.save()
        
    def _set_response(self, environ, start_response, oid_request, identity_uri):
        '''Add Attribute exchange parameters to the response if OpenID Relying
        Party requested them
        
        @type oid_request: openid.server.server.CheckIDRequest
        @param oid_request: OpenID Check ID request
        @rtype: basestring
        @return: WSGI response
        '''   
        # Process any request for additional attributes contained in the query
        # from the Relying Party
        try:
            response = self._create_response(oid_request, 
                                             identifier=identity_uri)
            
        except (OpenIDProviderMissingRequiredAXAttrs,
                OpenIDProviderMissingAXResponseHandler):
            log.error('The requesting Relying Party requires additional '
                      'attributes which this site isn\'t configured to '
                      'provide.')
            raise HTTPUnauthorized()
            
        except OpenIDProviderReloginRequired, e:
            log.error('An error occurred setting return attribute parameters '
                'required by the Relying Party requesting your ID.')
            raise HTTPUnauthorized()
            
        except Exception, e:
            log.error("%s type exception raised setting additional attributes "
                      " in the response: %s", 
                      e.__class__.__name__, 
                      traceback.format_exc())
            raise HTTPUnauthorized()
    
        webresponse = self.oidserver.encodeResponse(self.oid_response)
        hdr = webresponse.headers.items()
        
        # If the content length exceeds the maximum to represent on a URL,
        # it's rendered as a form instead
        # FIXME: Got rid out oid_response.renderAsForm() test as it doesn't 
        # give consistent answers.  
        #
        # The FORM_MATCH_TEXT test detects whether the response needs to be 
        # wrapped in the FORM_RESP_WRAPPER_TMPL Javascript.  This is only
        # needed when this Provider is return key/values pairs back to the 
        # RP as a POST'ed form
        if webresponse.body.startswith(
                                OpenIDProviderMiddleware.FORM_MATCH_TEXT):
            # Wrap in HTML with Javascript OnLoad to submit the form
            # automatically without user intervention
            response = OpenIDProviderMiddleware.FORM_RESP_WRAPPER_TMPL % \
                                                        webresponse.body
        else:
            response = webresponse.body
            
        hdr += [('Content-type', 'text/html' + self.charset),
                ('Content-length', str(len(response)))]
        
        log.debug("Sending response to Relying Party:\n\nheader=%r\nbody=%r",
                  hdr, response)
            
        start_response('%d %s' % (webresponse.code,
                                  httplib.responses[webresponse.code]),
                       hdr)
        return [response]        

 