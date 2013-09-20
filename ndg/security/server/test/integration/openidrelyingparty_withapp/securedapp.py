#!/usr/bin/env python
"""NDG Security test harness for authorisation middleware used to secure an
application

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securedapp.py [port #]
if __name__ == '__main__':
    import sys
    import os
    from os.path import dirname, abspath
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 7080
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'securedapp.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)