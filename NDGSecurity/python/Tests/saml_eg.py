from ndg.saml.saml2.core import (AttributeQuery, SAMLVersion, Issuer, Subject,
                                 NameID, Attribute, XSStringAttributeValue)
from uuid import uuid4
from datetime import datetime

attributeQuery = AttributeQuery()
attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
attributeQuery.id = str(uuid4())
attributeQuery.issueInstant = datetime.utcnow()

attributeQuery.issuer = Issuer()
attributeQuery.issuer.format = Issuer.X509_SUBJECT
attributeQuery.issuer.value = '/O=NDG/OU=BADC/CN=PolicyInformationPoint'
                
attributeQuery.subject = Subject()  
attributeQuery.subject.nameID = NameID()
attributeQuery.subject.nameID.format = NameID.X509_SUBJECT
attributeQuery.subject.nameID.value = '/O=NDG/OU=BADC/CN=PhilipKershaw'

# special case handling for 'LastName' attribute
emailAddressAttribute = Attribute()
emailAddressAttribute.name = "urn:esg:email:address"
emailAddressAttribute.nameFormat = "%s#%s" % (
                                XSStringAttributeValue.TYPE_NAME.namespaceURI,
                                XSStringAttributeValue.TYPE_NAME.localPart)

emailAddress = XSStringAttributeValue()
emailAddress.value = 'pjk@somewhere.ac.uk'
emailAddressAttribute.attributeValues.append(emailAddress)

attributeQuery.attributes.append(emailAddressAttribute)

# Convert to ElementTree representation
from ndg.saml.xml.etree import AttributeQueryElementTree, prettyPrint

elem = AttributeQueryElementTree.toXML(attributeQuery)

# Serialise as string
xmlOut = prettyPrint(elem)
print(xmlOut)


