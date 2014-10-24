'''
Security middleware - set-up configuration items

P J Kershaw 18/03/08
'''
import logging
log = logging.getLogger(__name__)

class ndg:
    '''Class structure to define a namespace for SSO Client config attached
    Pylons global variable 'g'
    '''
    class security:
        class common:
            class sso:
                class cfg:
                    '''Placeholder for server and sslServer attributes'''
                class state:
                    '''State information - return to URL should be set each 
                    time a new page is loaded.  In ows_server this is handled
                    by setting it in ndgPage.kid a template that is extended by
                    all Browse pages.'''
                    returnToURL = ''
                    b64encReturnToURL = ''

class SSOMiddleware(object):
    
    def __init__(self, app, cfg, appGlobals, **kw):
        
        log.debug("SSOMiddleware.__init__ ...")
        self.app = app

        ndg.security.common.sso.cfg = SSOClientConfig(cfg, **kw)
        appGlobals.ndg = ndg

    def __call__(self, environ, start_response):
        log.debug("SSOMiddleware.__call__ ...")
        
        return self.app(environ, start_response)

import sys
from ConfigParser import SafeConfigParser as ConfigParser
        
class SSOClientConfigError(Exception):
    """Handle errors from parsing security config items"""

class SSOClientConfig(object):
    """Get Security related parameters from the Pylons NDG config file"""

    def __init__(self, cfg=None, **parseKw):
        '''Get settings for Single Sign On client'''
        
        if isinstance(cfg, basestring):
            # Assume file path to be read
            self.read(cfg)
        else:
            # Assume existing config type object
            self.cfg = cfg

        if self.cfg:
            self.parse(**parseKw)
            
    def read(self, cfgFilePath):
        '''Read config file into SafeConfigParser instance
        
        @type cfgFilePath: pylons config file object
        @param cfgFilePath: reference to NDG configuration file.'''
        self.cfg = ConfigParser()
        self.cfg.read(cfgFilePath)
 
    def parse(self, defSection='DEFAULT', layoutSection='layout'):
        '''Extract content of config file object into self'''
       
        # Hostname
        self.server=self.cfg.get(defSection, 'server')

        # For secure connections
        self.sslServer = self.cfg.get(defSection, 'sslServer')
                      
        # Where Are You From URI - defaults to server root if not set in
        # config - i.e. assumes same host as client 
        if self.cfg.has_option(defSection, 'wayfURI'):        
            self.wayfuri = self.cfg.get(defSection, 'wayfURI')
        else:
            self.wayfuri = '%s/wayf' % self.server

        # Logout URI can reside on this server or somewhere else determined by
        # the logout config file setting
        if self.cfg.has_option(defSection, 'logoutURI'):        
            self.logoutURI = self.cfg.get(defSection, 'logoutURI')
        else:
            self.logoutURI = '%s/logout' % self.server
            
        self.localLink=self.cfg.get(layoutSection, 'localLink', None)
        self.localImage=self.cfg.get(layoutSection, 'localImage', None)
        self.localAlt=self.cfg.get(layoutSection, 'localAlt', 'Visit Local Site')
        self.ndgLink=self.cfg.get(layoutSection, 'ndgLink', 'http://ndg.nerc.ac.uk')
        self.ndgImage=self.cfg.get(layoutSection, 'ndgImage', None)
        self.ndgAlt=self.cfg.get(layoutSection, 'ndgAlt','Visit NDG')
        self.stfcLink=self.cfg.get(layoutSection, 'stfcLink')
        self.stfcImage=self.cfg.get(layoutSection, 'stfcImage')
        self.helpIcon=self.cfg.get(layoutSection, 'helpIcon')
        self.LeftAlt=self.cfg.get(layoutSection, 'HdrLeftAlt')
        self.LeftLogo=self.cfg.get(layoutSection, 'HdrLeftLogo')
        self.pageLogo="bodcHdr"
        self.icons_xml=self.cfg.get(layoutSection,'Xicon')
        self.icons_plot=self.cfg.get(layoutSection,'plot')
        self.icons_prn=self.cfg.get(layoutSection, 'printer')
        
        self.disclaimer = self.cfg.get(defSection, 'disclaimer')
   
        # TODO: re-include security settings to enable logout via Session
        # Manager