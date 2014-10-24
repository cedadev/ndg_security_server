#/usr/bin/env python
"""Test urllib2 client with NDG Security error handling

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import urllib2

def makeRequest(endpoint):
    try:
        req = urllib2.Request(endpoint)
        handle = urllib2.urlopen(req)
        
    except urllib2.HTTPError, e:
        if e.code == 401:
            # Force ndg.security authentication to be triggered for the user to 
            # sign in.  Once included within a Pylons controller, uncomment the
            # abort call to activate and remove the pass statement
            log.debug("Code = %d" % e.code)
            log.debug("Headers:\n\n %s" % e.headers)
            log.debug("Response:\n\n %s" % e.read())
            #abort(401) 

        elif e.code == 403:
            # User is authenticated but doesn't have the required permissions 
            # or an error occurred in the authorization process
            # Read response
            response = e.read()
            
            # Send response to user
            start_response("%d %s" % (e.code, e.msg), e.headers.dict.items())
            return response
        else:
            # Other error handling  - just calling raise here would probably 
            # trigger a '500 Internal Error'
            raise

if __name__ == "__main__":
    endpoint = 'http://ndg3beta.badc.rl.ac.uk/cows/famous_control_month/wms?REQUEST=GetContext'
    # Send via tcpmon ...
    #endpoint = 'http://localhost:6000/cows/famous_control_month/wms?REQUEST=GetContext'
    response = makeRequest(endpoint)
