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
        # 'test' user is for SSL client based authentication where the test
        # certificate DN has a Common Name = test
        if userId.endswith("/openid/PhilipKershaw"):
            return [
                'postdoc',
                'staff', 
                'undergrad', 
                'coapec'
            ]
        elif userId == 'test':
            return [
                'staff', 
            ]
        else:
            return ['guest']
