'''
Security middleware - set-up configuration items

P J Kershaw 18/03/08
'''
import authkit.authenticate
from beaker.middleware import SessionMiddleware
        
from os.path import expandvars as xpdvars
from os.path import dirname
import logging
log = logging.getLogger(__name__)

class ndg:
    '''Class structure to define a namespace for SSO Service config attached
    Pylons global variable 'g'
    '''
    class security:
        class server:
            class sso:
                cfg = None
                class state:
                    '''State information specific to server side'''
                    trustedIdPs = {}
                
        class common:
            '''Client class is also needed for BaseController handler to handle
            responses from Single Sign On IdP'''
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
            
    def __init__(self, app, g, app_conf, **kw):
        log.debug("SSOMiddleware.__init__ ...")
        ndg.security.server.sso.cfg = SSOServiceConfig(app_conf['configfile'], 
                                                       **kw)
        
        # Copy into client for the benefit of
        # ndg.security.client.ssoclient.ssoclient.lib.base.BaseController
        # used to process responses back from SSO IdP
        ndg.security.common.sso.cfg.server = ndg.security.server.sso.cfg.server
        ndg.security.common.sso.cfg.sslServer = \
                                        ndg.security.server.sso.cfg.sslServer
            
        g.ndg = ndg
        self.globals = g
    
        # OpenID Middleware
        app = authkit.authenticate.middleware(app, app_conf)
        app = SessionMiddleware(app)

        self.app = app
                
    def __call__(self, environ, start_response):
        return self.app(environ, start_response)


import sys
from ConfigParser import SafeConfigParser as ConfigParser
from ndg.security.common.wssecurity import WSSecurityConfig

class SSOServiceConfigError(Exception):
    """Handle errors from parsing security config items"""
       
class SSOServiceConfig(object):
    """Get Security related parameters from the Pylons NDG config file"""

    def __init__(self, cfg=None, **parseKw):
        '''Get PKI settings for Attribute Authority and Session Manager from
        the configuration file
        
        @type cfg: config file object or string
        @param cfg: reference to NDG configuration file or config file object
        '''
        
        self.wss = {}
        
        if isinstance(cfg, basestring):
            # Assume file path to be read
            self.read(cfg)
        else:
            # Assume existing config type object
            self.cfg = cfg

        if self.cfg:
            self.parse(**parseKw)

        
    def read(self, cfgFilePath):
        '''Read content of config file into object'''
        self.cfg = ConfigParser(defaults={'here': dirname(cfgFilePath)})
        self.cfg.read(cfgFilePath)
 

    def parse(self, 
              defSection='DEFAULT', 
              layoutSection='layout',
              wssSection='WS-Security'):
        '''Extract content of config file object into self'''
              
        if self.cfg.has_option(defSection, 'tracefile'):        
            self.tracefile = eval(self.cfg.get(defSection,'tracefile'))    
        else:
            self.tracefile = None
            
        if self.cfg.has_option(defSection, 'sessionMgrURI'):
            self.smURI = self.cfg.get(defSection, 'sessionMgrURI')
        else:
            self.smURI = None
            
        if self.cfg.has_option(defSection, 'sessionManagerEnvironKeyName'):        
            self.smEnvironKeyName = self.cfg.get(defSection, 
                                             'sessionManagerEnvironKeyName')
        else:
            self.smEnvironKeyName = None
            
        if self.cfg.has_option(defSection, 'attributeAuthorityURI'):        
            self.aaURI = self.cfg.get(defSection, 'attributeAuthorityURI')
        else:
            self.aaURI = None
            
        if self.cfg.has_option(defSection, 'attributeAuthorityEnvironKeyName'):        
            self.aaEnvironKeyName = self.cfg.get(defSection, 
                                             'attributeAuthorityEnvironKeyName')
        else:
            self.aaEnvironKeyName = None
        
        # ... for SSL connections to security web services
        try:
            self.sslCACertFilePathList = \
            xpdvars(self.cfg.get(defSection, 'sslCACertFilePathList')).split()
                
        except AttributeError:
            raise SSOServiceConfigError, \
                        'No "sslCACertFilePathList" security setting'


        # HTTP Proxy setting for web service connections...
        
        # Override an http_proxy env setting  
        if self.cfg.has_option(defSection, 'httpProxyHost'):
            self.httpProxyHost = self.cfg.get(defSection, 'httpProxyHost')
        else:
            self.httpProxyHost = None
        
        # Set this to True if the http_proxy environment variable should be
        # ignored in this case
        if self.cfg.has_option(defSection, 'noHttpProxyList'):
            self.noHttpProxyList = self.cfg.getboolean(defSection, 
                                                          'noHttpProxyList')
        else:
            self.noHttpProxyList = False
            
            
        # If no separate WS-Security config file is set then read these params
        # from the current config file
        if self.cfg.has_option(defSection, 'wssCfgFilePath'):
            path = self.cfg.get(defSection,'wssCfgFilePath', None) 
            wssCfgFilePath = xpdvars(path)
        else:
            wssCfgFilePath = None
            
        wss = WSSecurityConfig(cfg=wssCfgFilePath or self.cfg)
        wss.parse(section=wssSection)

        
        # Cast to standard dict because WSSecurityConfig object can't be
        # passed via **kw and dict(wss) doesn't work 
        # TODO: check for cleaner solution - dict(wss)
        self.wss = dict(wss.items())


        # Hostname
        self.server = self.cfg.get(defSection, 'server', '')

        # For secure connections
        self.sslServer = self.cfg.get(defSection, 'sslServer', '')
        
        # These URLs are referred from template files
        self.getCredentials = '%s/getCredentials' % self.sslServer       
        self.logoutURI = '%s/logout' % self.server
                      
        # Where Are You From URI          
        self.wayfuri='%s/wayf' % self.server

        # Flag to enable OpenID interface
        if self.cfg.has_option(defSection, 'enableOpenID'):
            self.enableOpenID = self.cfg.getboolean(defSection, 'enableOpenID')
        else:
            self.enableOpenID = False
            
        # Optional - only required for a standalone SSO deployment
        if self.cfg.has_section(layoutSection):
            self.localLink=self.cfg.get(layoutSection, 'localLink', None)
            self.localImage=self.cfg.get(layoutSection, 'localImage', None)
            self.localAlt=self.cfg.get(layoutSection, 'localAlt', 
                                       'Visit Local Site')
            self.ndgLink=self.cfg.get(layoutSection, 'ndgLink', 
                                      'http://ndg.nerc.ac.uk')
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
        
        if self.cfg.has_option(defSection, 'disclaimer'):
            self.disclaimer = self.cfg.get(defSection, 'disclaimer')
        else:
            self.disclaimer = ''
            
            
    def __repr__(self):
        return '\n'.join(["%s=%s" % (k,v) for k,v in self.__dict__.items() \
                if k[:2] != "__"])
    