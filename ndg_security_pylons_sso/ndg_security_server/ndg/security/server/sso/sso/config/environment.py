"""Pylons environment configuration"""
import os
from os.path import dirname
from pylons import config

import ndg.security.server.sso.sso.lib.app_globals as app_globals
import ndg.security.server.sso.sso.lib.helpers
from ndg.security.server.sso.sso.config.routing import make_map

def load_environment(global_conf, app_conf):
    """Configure the Pylons environment via the ``pylons.config``
    object
    """
    # Pylons paths
    rootDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    configDir = None
    if 'configfile' in app_conf:
        from ConfigParser import SafeConfigParser as ConfigParser
        cfg = ConfigParser(defaults={'here': dirname(app_conf['configfile'])})
        cfg.read(app_conf['configfile'])
        if cfg.has_option('DEFAULT', 'configDir'):
            configDir = cfg.get('DEFAULT', 'configDir')
            
        if cfg.has_option('DEFAULT', 'templatesPackage'):
            templatesPackage = cfg.get('DEFAULT', 'templatesPackage')
        else:
            templatesPackage = 'ndg.security.server.sso.sso.templates'
            
            
    if configDir is None:
        configDir = rootDir
        
    paths = dict(root=configDir,
                 controllers=os.path.join(rootDir, 'controllers'),
                 static_files=os.path.join(configDir, 'public'),
                 templates=[os.path.join(configDir, 'templates')])

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, 
                    package='ndg.security.server.sso.sso',
                    template_engine='kid', paths=paths)

    config['routes.map'] = make_map()
    config['pylons.g'] = app_globals.Globals()
    config['pylons.h'] = ndg.security.server.sso.sso.lib.helpers

    # Customize templating options via this variable
    tmpl_options = config['buffet.template_options']

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)
    
    # Make a dedicated alias for SSO Service templates to avoid possible
    # conflicts when importing SSO Service code into another pylons project
    kidopts = {'kid.assume_encoding':'utf-8', 'kid.encoding':'utf-8'}
    
    config.add_template_engine('kid', 
                               templatesPackage,
                               kidopts,
                               alias='ndg.security.kid')