"""WSGI Middleware to set the use_lxml flags for ndg_xacml, ndg_saml and
ndg_security all to True.

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "13/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"

import logging
log = logging.getLogger(__name__)

log.info("Configuring to not use lxml")
use_lxml = False
from ndg.xacml import Config as XacmlConfig
XacmlConfig.use_lxml = use_lxml
from ndg.saml import Config as SamlConfig
SamlConfig.use_lxml = use_lxml
from ndg.soap import Config as SoapConfig
SoapConfig.use_lxml = use_lxml
from ndg.security.common.config import Config as SecurityConfig
SecurityConfig.use_lxml = use_lxml

class NoLxmlConfigMiddleware(object):
    """Middleware that does nothing other than causing ndg_xacml, ndg_saml and
    ndg_security to be loaded and setting to False their flags for forcing lxml
    to be used.
    """
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
        """Always delegates to the enclosed filter/app without doing anything
        else.

        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        return self._app(environ, start_response)
