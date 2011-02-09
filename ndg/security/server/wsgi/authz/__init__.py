"""WSGI Policy Enforcement Point Package

NERC DataGrid Project
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
from urlparse import urlunsplit
import httplib

from paste.cascade import Cascade
from paste.urlparser import StaticURLParser
from authkit.authenticate.multi import MultiHandler

from ndg.security.common.utils.classfactory import importClass
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.pep import SamlPepFilter
from ndg.security.server.wsgi.authz.result_handler import \
    PEPResultHandlerMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler.basic import \
    PEPResultHandlerMiddleware


class Http403ForbiddenStatusHandler(object):
    """Handler to catch HTTP 403 Forbidden responses.  It integrates with
    AuthKit's MultiHandler.  This enables the given middleware to be substituted
    into the WSGI stack should a 403 status be detected set from upstream
    middleware.
        
    @cvar TRIGGER_HTTP_STATUS_CODE: status code to catch - HTTP 403 Forbidden
    @type TRIGGER_HTTP_STATUS_CODE: basestring
    """
    TRIGGER_HTTP_STATUS_CODE = str(httplib.FORBIDDEN)
    
    @classmethod
    def intercept(cls, environ, status, headers):
        """Checker function for AuthKit Multihandler
        
        @type environ: dict
        @param environ: WSGI environment dictionary
        @type status: basestring
        @param status: HTTP response code set by application middleware
        that this intercept function is to protect
        @type headers: list
        @param headers: HTTP response header content"""
        
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
 
   
class AuthorisationFilter(object):
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
        application(s) to be protected.  An AuthKit MultiHandler is setup to 
        handle the latter.  PEPResultHandlerMiddleware handles the output
        set following an access denied decision
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
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
            app = Cascade([app, staticApp], catch=(httplib.NOT_FOUND,))

        pepPrefix = prefix + cls.PEP_PARAM_PREFIX
        pepFilter = SamlPepFilter.filter_app_factory(app, 
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
