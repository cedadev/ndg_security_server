""".. WSGI Policy Enforcement Point Package

Authorisation is managed within a WSGI filter architecture.  An authorisation \
WSGI filter is configured in a chain of filters to secure a given application. \ 
filter intercepts requests and either makes an access control or passes on an \
access control request to a third-party authorisation service to make the \
decision on its behalf.

When a decision is made, the filter enforces it by accepting the request, \
making an access denied response or flagging an error:

* Access Permitted: it passes on the HTTP request on to the next WSGI filter \
in the chain .  If there are now more filters, control will pass to the \
underlying application.
* Access Denied: it returns a HTTP 403 Forbidden response.  Other filters may \
intercept this response as required - e.g. to display a prettified error \
message to a browser client applying stylesheets and graphics etc.
* Error: if an error occurs a 500 response is returned.  Again, another filter \
could intercept this and perform some other appropriate action.

Filters have been developed for the Earth System Grid Federation.  These use a \
client-server architecture for authorisation.  A authorisation service - \
typically one per organisation - handles access control decisions.

In this case, the WSGI authorisation filter has a special component, a PEP \
(Policy Enforcement Point).  The PEP makes the requests to the authorisation \
service.  Inside the authorisation service a *PDP* (Policy *Decision* Point) \
makes access control decisions based on the incoming request from the PEP and \
access control policy that it holds.

The PEP *enforces* decisions it receives back from the authorisation service \
in the same way as described in the above bullets.

Using a client-server architecture is helpful as it enables the centralisation \
of authorisation policy across a range of services in a given organisation.  \
The drawback is that there is added complexity in managing the client-server \
interactions especially if these themselves need to be secured.

Equally it is possible to implement an authorisation filter which makes its \
own authorisation decisions without the need for a separate authorisation \
service.

.. NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "16/01/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)

import warnings
from time import time
from urllib.parse import urlunsplit
import http.client

from paste.urlparser import StaticURLParser
from authkit.authenticate.multi import MultiHandler

from ndg.security.common.utils.classfactory import importClass
from ndg.security.server.utils.paste_port import Cascade
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.pep import SamlPepFilter
from ndg.security.server.wsgi.authz.pep_xacml_profile import XacmlSamlPepFilter
from ndg.security.server.wsgi.authz.result_handler import \
    PEPResultHandlerMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler.basic import \
    PEPResultHandlerMiddleware


class Http403ForbiddenStatusHandler(object):
    """Handler to catch HTTP 403 Forbidden responses.  It integrates with
    AuthKit's MultiHandler.  This enables the given middleware to be substituted
    into the WSGI stack should a 403 status be detected set from upstream
    middleware.
        
    :cvar TRIGGER_HTTP_STATUS_CODE: status code to catch - HTTP 403 Forbidden
    :type TRIGGER_HTTP_STATUS_CODE: basestring
    """
    TRIGGER_HTTP_STATUS_CODE = str(http.client.FORBIDDEN)
    
    @classmethod
    def intercept(cls, environ, status, headers):
        """Checker function for AuthKit Multihandler
        
        :type environ: dict
        :param environ: WSGI environment dictionary
        :type status: basestring
        :param status: HTTP response code set by application middleware
        that this intercept function is to protect
        :type headers: list
        :param headers: HTTP response header content"""
        
        if status.startswith(cls.TRIGGER_HTTP_STATUS_CODE):
            log.debug("Found [%s] status for URI path [%s]: invoking access "
                      "denied response",
                      cls.TRIGGER_HTTP_STATUS_CODE,
                      environ['PATH_INFO'])
            return True
        else:
            # No match - it's publicly accessible
            log.debug("The return status [%s] for this URI path [%s] didn't "
                      "match the trigger status [%s]",
                      status,
                      environ['PATH_INFO'],
                      cls.TRIGGER_HTTP_STATUS_CODE)
            return False

    
class AuthorisationFilterConfigError(Exception):
    """AuthorisationFilterBase configuration related exceptions"""
 
   
class AuthorisationFilterBase(object):
    '''NDG Security Authorisation filter wraps the Policy Enforcement Point 
    (PEP) filter to intercept requests and enforce access control decisions and
    result handler middleware which enables a customised response given an
    authorisation denied decision from the PEP filter.
    '''
    PEP_PARAM_PREFIX = 'pep.'
    RESULT_HANDLER_PARAMNAME = "resultHandler"
    RESULT_HANDLER_PARAM_PREFIX = RESULT_HANDLER_PARAMNAME + '.'
    RESULT_HANDLER_STATIC_CONTENT_DIR_PARAMNAME = 'staticContentDir'
    
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix='', **app_conf):
        """Set-up Policy Enforcement Point to enforce access control decisions
        based on the URI path requested and/or the HTTP response code set by
        application(s) to be protected.  An AuthKit ``MultiHandler`` is setup to 
        handle the latter.  ``PEPResultHandlerMiddleware`` handles the output
        set following an access denied decision
        
        :type app: callable following WSGI interface
        :param app: next middleware application in the chain      
        :type global_conf: dict        
        :param global_conf: ``PasteDeploy`` global configuration dictionary
        :type prefix: basestring
        :param prefix: prefix for configuration items
        :type app_conf: dict        
        :param app_conf: ``PasteDeploy`` application specific configuration \
        dictionary

        """
        # Allow for static content for use with PEP result handler middleware 
        resultHandlerParamPrefix = prefix + cls.RESULT_HANDLER_PARAM_PREFIX
        resultHandlerStaticContentDirParamName = \
                                resultHandlerParamPrefix + \
                                cls.RESULT_HANDLER_STATIC_CONTENT_DIR_PARAMNAME
        
        resultHandlerStaticContentDir = app_conf.get(
                                    resultHandlerStaticContentDirParamName)
        if resultHandlerStaticContentDir is not None:    
            staticApp = StaticURLParser(resultHandlerStaticContentDir)
            app = Cascade([app, staticApp], catch=(http.client.NOT_FOUND,))

        pepPrefix = prefix + cls.PEP_PARAM_PREFIX
        pepFilter = cls.PEP_FILTER.filter_app_factory(app, 
                                                      global_conf, 
                                                      prefix=pepPrefix, 
                                                      **app_conf)
        
        # Now add the multi-handler to enable result handler to be invoked on
        # 403 forbidden status from upstream middleware 
        app = MultiHandler(pepFilter)

        resultHandlerClassName = app_conf.pop(
                                            prefix+cls.RESULT_HANDLER_PARAMNAME, 
                                            None)
        if resultHandlerClassName is None:
            resultHandler = PEPResultHandlerMiddleware
        else:
            resultHandler = importClass(resultHandlerClassName,
                                    objectType=PEPResultHandlerMiddlewareBase)
                               
        app.add_method(resultHandler.__class__.__name__,
                       resultHandler.filter_app_factory,
                       global_conf,
                       prefix=resultHandlerParamPrefix,
                       **app_conf)
        
        app.add_checker(resultHandler.__class__.__name__, 
                        Http403ForbiddenStatusHandler.intercept)
        
        return app


class AuthorisationFilter(AuthorisationFilterBase):
    '''.. AuthorisationFilter implementation that uses the pure SAML in \
    requests to the PEP.
    
    ``AuthorisationFilter`` is a WSGI filter that can be configured to wrap a \
    given WSGI application and apply an authorisation policy.  The filter \
    itself uses a client/server pattern: a Policy Enforcement Point (PEP) in \
    the filter calls out to a separate PDP (Policy Decision Point) running in \
    an authorisation web service.  This service uses a uses a SAML/SOAP \
    binding for communication.  The PEP makes queries using the SAML \
    Authorisation Decision Query.  This allows querying based on requested \
    URI and HTTP method used (e.g. POST, PUT, GET).  This service is \
    compatible with the ESGF Security Architecture.  This means that this \
    filter can be configured to callout to an ESGF implementation of the \
    Authorisation Service.

    :requires: ndg_saml
    '''
    PEP_FILTER = SamlPepFilter


class XACMLAuthorisationFilter(AuthorisationFilterBase):
    '''.. AuthorisationFilter implementation that uses the XACML profile for \
    SAML when making requests to the PEP.
    
    This is a variant on the \
    ``ndg.security.server.wsgi.authz.AuthorisationFilter``.  The XACML name \
    relates to the format of messages used to make queries to the \
    *Authorisation Service*.  Like the ``AuthorisationFilter``, it uses a \
    SAML/SOAP binding for communication with the latter.  The SAML \
    Authorisation Decision Query is modified to use features from XACML, the \
    eXtensible Mark-up Language.  XACML is both a data model and an XML \
    serialisation for expressing access control policies and also for \
    exchanging messages for communicating authorisation queries and \
    responses.  The latter is what is being exploited here.  This allows a \
    richer functionality for expressing access queries, for example the \
    ability to make decisions based on XQuery'd content and also to allow \
    for a richer code list for access control decisions.

    :requires: ndg_saml, ndg_xacml
    '''
    PEP_FILTER = XacmlSamlPepFilter
