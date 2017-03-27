"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority
                                                                                
NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/07/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:siteAUserRoles.py 4371 2008-10-29 09:44:51Z pjkersha $'

from datetime import timedelta
from uuid import uuid4

from ndg.saml.common.xml import SAMLConstants
from ndg.saml.saml2.core import (Assertion, Attribute, AttributeStatement, 
                                 Issuer, SAMLVersion, Subject, NameID, 
                                 Conditions, XSStringAttributeValue)

from ndg.security.common.saml_utils.esgf import (ESGFSamlNamespaces,
                                                 ESGFGroupRoleAttributeValue)
from ndg.security.common.openssl import X500DN
from ndg.security.server.attributeauthority import (AttributeInterface, 
                                                    InvalidRequestorId, 
                                                    AttributeNotKnownError, 
                                                    AttributeReleaseDenied, 
                                                    UserIdNotKnown)
from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.test.test_util import TestUserDatabase


class TestUserRoles(AttributeInterface):
    """Test User Roles class dynamic import for Attribute Authority"""
    ATTRIBUTE_NAMES = ()
    ATTRIBUTE_VALUES = ()

    SAML_ATTRIBUTE_NAMES = ATTRIBUTE_NAMES + (
        ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME,
        ESGFSamlNamespaces.FIRSTNAME_ATTRNAME, 
        ESGFSamlNamespaces.LASTNAME_ATTRNAME,
        'urn:esg:sitea:grouprole'
    )
    
    SAML_ATTRIBUTE_VALUES = (
        ATTRIBUTE_VALUES,
        ('p.kershaw@somewhere.ac.uk',),
        ('Philip',),
        ('Kershaw',),
        (('siteagroup', 'default'),)
    )
    
    SAML_ATTRIBUTE_FRIENDLY_NAMES = ('',)*len(ATTRIBUTE_NAMES) + (
        "EmailAddress",
        "FirstName",
        "LastName",
        "groupRole"
    )
    SAML_ATTRIBUTE_FORMATS = (
        SAMLConstants.XSD_NS+"#"+XSStringAttributeValue.TYPE_LOCAL_NAME,) * (
        len(SAML_ATTRIBUTE_NAMES)-1) + \
        (ESGFGroupRoleAttributeValue.TYPE_LOCAL_NAME, )
    
    SAML_ATTRIBUTES = []
    
    name, val, vals, format, friendlyName = (None, None, None, None, None)
    for name, vals, format, friendlyName in zip(SAML_ATTRIBUTE_NAMES,
                                                SAML_ATTRIBUTE_VALUES,
                                                SAML_ATTRIBUTE_FORMATS,
                                                SAML_ATTRIBUTE_FRIENDLY_NAMES):
        SAML_ATTRIBUTES.append(Attribute())
        SAML_ATTRIBUTES[-1].name = name
        SAML_ATTRIBUTES[-1].nameFormat = format
        SAML_ATTRIBUTES[-1].friendlyName = friendlyName
        for val in vals:
            if isinstance(val, tuple):
                SAML_ATTRIBUTES[-1].attributeValues.append(
                                                ESGFGroupRoleAttributeValue())
                SAML_ATTRIBUTES[-1].attributeValues[-1].value = val
            else:
                SAML_ATTRIBUTES[-1].attributeValues.append(
                                                XSStringAttributeValue())
                SAML_ATTRIBUTES[-1].attributeValues[-1].value = val

    del name, val, vals, format, friendlyName
    
    # 8 hours validity for issued assertions
    SAML_ASSERTION_LIFETIME = 8*60*60
    
    VALID_USER_IDS = ("https://openid.localhost/philip.kershaw",
                      TestUserDatabase.OPENID_URI)
    VALID_REQUESTOR_IDS = BaseTestCase.VALID_REQUESTOR_IDS
    
    INSUFFICIENT_PRIVILEGES_REQUESTOR_ID = X500DN.from_string(
                                        "/O=Site B/CN=Authorisation Service")
    
    def __init__(self, propertiesFilePath=None):
        pass

    def getRoles(self, userId):
        return TestUserRoles.ATTRIBUTE_VALUES

    def getAttributes(self, attributeQuery, response):
        '''Test Attribute Authority SAML Attribute Query interface'''
        
        userId = attributeQuery.subject.nameID.value
        requestedAttributeNames = [attribute.name 
                                   for attribute in attributeQuery.attributes]
        if attributeQuery.issuer.format != Issuer.X509_SUBJECT:
            raise InvalidRequestorId('Requestor issuer format "%s" is invalid' %
                                     attributeQuery.issuerFormat.value)
            
        requestorId = X500DN.fromString(attributeQuery.issuer.value)
        
        if userId not in TestUserRoles.VALID_USER_IDS:
            raise UserIdNotKnown('Subject Id "%s" is not known to this '
                                 'authority' % userId)
            
        if requestorId not in TestUserRoles.VALID_REQUESTOR_IDS:
            raise InvalidRequestorId('Requestor identity "%s" is invalid' %
                                     requestorId)
        
        unknownAttrNames = [attrName for attrName in requestedAttributeNames
                            if attrName not in 
                            TestUserRoles.SAML_ATTRIBUTE_NAMES]
        
        if len(unknownAttrNames) > 0:
            raise AttributeNotKnownError("Unknown attributes requested: %r" %
                                         unknownAttrNames)
            
        if requestorId == TestUserRoles.INSUFFICIENT_PRIVILEGES_REQUESTOR_ID:
            raise AttributeReleaseDenied("Attribute release denied for the "
                                         'requestor "%s"' % requestorId)
        
        # Create a new assertion to hold the attributes to be returned
        assertion = Assertion()
        
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = response.issueInstant
    
        assertion.issuer = Issuer()
        assertion.issuer.value = response.issuer.value
        assertion.issuer.format = Issuer.X509_SUBJECT
        
        assertion.conditions = Conditions()
        assertion.conditions.notBefore = assertion.issueInstant
        assertion.conditions.notOnOrAfter = assertion.conditions.notBefore + \
            timedelta(seconds=TestUserRoles.SAML_ASSERTION_LIFETIME)
        
        assertion.subject = Subject()  
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = attributeQuery.subject.nameID.format
        assertion.subject.nameID.value = attributeQuery.subject.nameID.value

        attributeStatement = AttributeStatement()
        
        # Add test set of attributes
        for name in requestedAttributeNames:
            attributeFound = False
            for attribute in TestUserRoles.SAML_ATTRIBUTES:
                if attribute.name == name:
                    attributeFound = True
                    break
            
            if attributeFound:
                attributeStatement.attributes.append(attribute)
            else:
                raise AttributeNotKnownError("Unknown attribute requested: %s"%
                                             name)
 
        assertion.attributeStatements.append(attributeStatement)       
        response.assertions.append(assertion)
