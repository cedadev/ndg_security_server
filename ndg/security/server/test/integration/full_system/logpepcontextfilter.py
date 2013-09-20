"""Middleware to log the request and response stored in the session.

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "18/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

from ndg.security.server.wsgi.authz.pep import SamlPepFilterBase

from ndg.saml.saml2.core import (AuthzDecisionQuery,
                                 Response)
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery
from ndg.saml.xml.etree import (AuthzDecisionQueryElementTree,
                                ResponseElementTree)
from ndg.saml.xml.etree_xacml_profile import (
    XACMLAuthzDecisionQueryElementTree)

import ndg.xacml.utils.etree as etree_utils

class LogPepContextFilterMiddleware(object):
    def __init__(self, app, global_conf, **app_conf):
        self._app = app

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        '''Function signature for Paste Deploy filter

        @type app: callable following WSGI interface
        @param app: next middleware application in the chain
        @type app_conf: dict
        @param app_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for app_conf parameters e.g. 'ndgsecurity.' -
        enables other global configuration parameters to be filtered out
        @type local_conf: dict
        @param local_conf: PasteDeploy application specific configuration
        dictionary
        '''
        return cls(app, app_conf, **local_conf)

    def __call__(self, environ, start_response):
        """Logs the request and response stored in the session.

        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        session = environ.get('beaker.session.ndg.security')
        if session:
            pepCtx = session.get(SamlPepFilterBase.PEPCTX_SESSION_KEYNAME)
            if pepCtx:
                request = pepCtx.get(SamlPepFilterBase.PEPCTX_REQUEST_SESSION_KEYNAME)
                if isinstance(request, AuthzDecisionQuery):
                    requestEtree = AuthzDecisionQueryElementTree.toXML(request)
                    log.debug("AuthzDecisionQuery:\n%s",
                              etree_utils.prettyPrint(requestEtree))
                elif isinstance(request, XACMLAuthzDecisionQuery):
                    requestEtree = XACMLAuthzDecisionQueryElementTree.toXML(request)
                    log.debug("XACMLAuthzDecisionQuery:\n%s",
                              etree_utils.prettyPrint(requestEtree))
                else:
                    log.error("Request stored in session is of unknown type: %s"
                              % type(request))

                response = pepCtx.get(SamlPepFilterBase.PEPCTX_RESPONSE_SESSION_KEYNAME)
                if isinstance(response, Response):
                    responseEtree = ResponseElementTree.toXML(response)
                    log.debug("Response:\n%s",
                              etree_utils.prettyPrint(responseEtree))
                else:
                    log.error("Response stored in session is of unknown type: %s"
                              % type(response))

                timestamp = pepCtx.get(SamlPepFilterBase.PEPCTX_TIMESTAMP_SESSION_KEYNAME)
                log.debug("Timestamp: %s", timestamp)
            log.debug("No PEP context found in session.")
        return self._app(environ, start_response)
