"""NDG Attribute Authority attribute interface class - acts as an interface 
between the data centre's user roles configuration and the Attribute Authority

Use an alternative config here to 
ndg.security.test.config.attributeauthority.sitea.siteAUserRoles.TestUserRoles
to test multi user access
                                                                                
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/07/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from ndg.security.server.attributeauthority import AttributeInterface

class TestUserRoles(AttributeInterface):
    """Test User Roles class dynamic import for Attribute Authority"""

    def __init__(self, propertiesFilePath=None):
        pass

    def getRoles(self, userId):
        if userId.endswith("/openid/PhilipKershaw"):
            return [
                'urn:siteA:security:authz:1.0:attr:postdoc',
                'urn:siteA:security:authz:1.0:attr:staff', 
                'urn:siteA:security:authz:1.0:attr:undergrad', 
                'urn:siteA:security:authz:1.0:attr:coapec'
            ]
        else:
            return ['urn:siteA:security:authz:1.0:attr:guest']
