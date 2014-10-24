"""Pylons environment configuration"""
import os

from pylons import config

import authtest.lib.app_globals as app_globals
import authtest.lib.helpers
from authtest.config.routing import make_map

def load_environment(global_conf, app_conf):
    """Configure the Pylons environment via the ``pylons.config``
    object
    """
    # Pylons paths
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = dict(root=root,
                 controllers=os.path.join(root, 'controllers'),
                 static_files=os.path.join(root, 'public'),
                 templates=[os.path.join(root, 'templates')])

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, package='authtest',
                    #template_engine='mako', 
                    template_engine='kid', 
                    paths=paths)

    config['routes.map'] = make_map()
    config['pylons.g'] = app_globals.Globals()
    config['pylons.h'] = authtest.lib.helpers

    # Customize templating options via this variable
    tmpl_options = config['buffet.template_options']

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)
#    kidopts = {'kid.assume_encoding':'utf-8', 'kid.encoding':'utf-8'}
#    config.add_template_engine('kid', 'authtest.templates', kidopts)

