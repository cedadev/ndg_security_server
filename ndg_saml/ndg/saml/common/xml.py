"""SAML Common XML module

Implementation of SAML 2.0 for NDG Security

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "23/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.saml.xml import XMLConstants    


class SAMLConstants(XMLConstants):
    '''XML related constants used in the SAML specifications.
    @cvar POST_METHOD: HTTP Request Method - POST.                           
    @type POST_METHOD: string                                                 
    @cvar GET_METHOD: HTTP Method - GET.                                     
    @type GET_METHOD: string                                                  
    @cvar SCHEMA_DIR: Directory, on the classpath, schemas are located in.   
    @type SCHEMA_DIR: string                                                  
    @cvar XML_SCHEMA_LOCATION: XML core schema system Id.                    
    @type XML_SCHEMA_LOCATION: string                                         
    @cvar XMLSIG_SCHEMA_LOCATION:  XML Signature schema Id.                  
    @type XMLSIG_SCHEMA_LOCATION: string                                      
    @cvar XMLENC_SCHEMA_LOCATION: XML Encryption schema Id.                  
    @type XMLENC_SCHEMA_LOCATION: string                                      
    @cvar SOAP11ENV_SCHEMA_LOCATION:  SOAP 1.1 schema Id.                    
    @type SOAP11ENV_SCHEMA_LOCATION: string                                   
    @cvar SOAP11ENV_NS:  SOAP 1.1 Envelope XML namespace.                    
    @type SOAP11ENV_NS: string                                                
    @cvar SOAP11ENV_PREFIX:  SOAP 1.1 Envelope QName prefix.                 
    @type SOAP11ENV_PREFIX: string                                            
    @cvar PAOS_NS:  Liberty PAOS XML Namespace.                              
    @type PAOS_NS: string                                                     
    @cvar PAOS_PREFIX:  Liberty PAOS QName prefix.                           
    @type PAOS_PREFIX: string                                                 
    @cvar SAML10_SCHEMA_LOCATION: SAML 1.0 Assertion schema system Id.       
    @type SAML10_SCHEMA_LOCATION: string                                      
    @cvar SAML11_SCHEMA_LOCATION: SAML 1.1 Assertion schema system Id.       
    @type SAML11_SCHEMA_LOCATION: string                                      
    @cvar SAML1_NS: SAML 1.X XML namespace.                                  
    @type SAML1_NS: string                                                    
    @cvar SAML10P_SCHEMA_LOCATION: SAML 1.0 Protocol schema system Id.       
    @type SAML10P_SCHEMA_LOCATION: string                                     
    @cvar SAML11P_SCHEMA_LOCATION: SAML 1.1 Protocol schema system Id.       
    @type SAML11P_SCHEMA_LOCATION: string                                     
    @cvar SAML10P_NS: SAML 1.X protocol XML namespace.                       
    @type SAML10P_NS: string                                                  
    @cvar SAML11P_NS: SupportEnumeration.                                    
    @type SAML11P_NS: string                                                  
    @cvar SAML1P_PREFIX: SAML 1.X Protocol QName prefix.                     
    @type SAML1P_PREFIX: string                                               
    @cvar SAML1_PREFIX: SAML 1.X Assertion QName prefix.                     
    @type SAML1_PREFIX: string                                                
    @cvar SAML1MD_NS: SAML 1 Metadata extension XML namespace.               
    @type SAML1MD_NS: string                                                  
    @cvar SAML1MD_SCHEMA_LOCATION: SAML 1 Metadata extension schema system Id.
    @type SAML1MD_SCHEMA_LOCATION: string                                      
    @cvar SAML1MD_PREFIX: SAML 1 Metadata extension namespace prefix.         
    @type SAML1MD_PREFIX: string                                               
    @cvar SAML1_ARTIFACT_BINDING_URI: URI for SAML 1 Artifact binding.        
    @type SAML1_ARTIFACT_BINDING_URI: string                                   
    @cvar SAML1_POST_BINDING_URI: URI for SAML 1 POST binding.                
    @type SAML1_POST_BINDING_URI: string                                       
    @cvar SAML1_SOAP11_BINDING_URI: URI for SAML 1 SOAP 1.1 binding.          
    @type SAML1_SOAP11_BINDING_URI: string                                     
    @cvar SAML20_SCHEMA_LOCATION: SAML 2.0 Assertion schema Id.               
    @type SAML20_SCHEMA_LOCATION: string                                       
    @cvar SAML20_NS: SAML 2.0 Assertion XML Namespace.                        
    @type SAML20_NS: string                                                    
    @cvar SAML20_PREFIX: SAML 2.0 Assertion QName prefix.                     
    @type SAML20_PREFIX: string                                                
    @cvar SAML20P_SCHEMA_LOCATION: SAML 2.0 Protocol schema Id.               
    @type SAML20P_SCHEMA_LOCATION: string                                      
    @cvar SAML20P_NS: SAML 2.0 Protocol XML Namespace.                        
    @type SAML20P_NS: string                                                   
    @cvar SAML20P_PREFIX: SAML 2.0 Protocol QName prefix.                     
    @type SAML20P_PREFIX: string                                               
    @cvar SAML20PTHRPTY_SCHEMA_LOCATION: SAML 2.0 Protocol Third-party extension schema Id.
    @type SAML20PTHRPTY_SCHEMA_LOCATION: string                                             
    @cvar SAML20PTHRPTY_NS: SAML 2.0 Protocol XML Namespace.                               
    @type SAML20PTHRPTY_NS: string                                                          
    @cvar SAML20PTHRPTY_PREFIX: SAML 2.0 Protocol QName prefix.                            
    @type SAML20PTHRPTY_PREFIX: string                                                      
    @cvar SAML20MD_SCHEMA_LOCATION: SAML 2.0 Metadata schema Id.                           
    @type SAML20MD_SCHEMA_LOCATION: string                                                  
    @cvar SAML20MD_NS: SAML 2.0 Metadata XML Namespace.                                    
    @type SAML20MD_NS: string                                                               
    @cvar SAML20MDQUERY_NS: SAML 2.0 Standalone Query Metadata extension XML namespace.    
    @type SAML20MDQUERY_NS: string                                                          
    @cvar SAML20MDQUERY_SCHEMA_LOCATION: SAML 2.0 Standalone Query Metadata extension schema system Id.
    @type SAML20MDQUERY_SCHEMA_LOCATION: string                                                         
    @cvar SAML20MDQUERY_PREFIX: SAML 2.0 Standalone Query Metadata extension prefix.                   
    @type SAML20MDQUERY_PREFIX: string                                                                  
    @cvar SAML20MD_PREFIX: SAML 2.0 Metadata QName prefix.
    @type SAML20MD_PREFIX: string
    @cvar SAML20AC_SCHEMA_LOCATION: SAML 2.0 Authentication Context schema Id.
    @type SAML20AC_SCHEMA_LOCATION: string
    @cvar SAML20AC_NS: SAML 2.0 Authentication Context XML Namespace.
    @type SAML20AC_NS: string
    @cvar SAML20AC_PREFIX: SAML 2.0 Authentication Context QName prefix.
    @type SAML20AC_PREFIX: string
    @cvar SAML20ECP_SCHEMA_LOCATION: SAML 2.0 Enhanced Client/Proxy SSO Profile schema Id.
    @type SAML20ECP_SCHEMA_LOCATION: string
    @cvar SAML20ECP_NS: SAML 2.0 Enhanced Client/Proxy SSO Profile XML Namespace.
    @type SAML20ECP_NS: string
    @cvar SAML20ECP_PREFIX: SAML 2.0 Enhanced Client/Proxy SSO Profile QName prefix.
    @type SAML20ECP_PREFIX: string
    @cvar SAML20DCE_SCHEMA_LOCATION: SAML 2.0 DCE PAC Attribute Profile schema Id.
    @type SAML20DCE_SCHEMA_LOCATION: string
    @cvar SAML20DCE_NS: SAML 2.0 DCE PAC Attribute Profile XML Namespace.
    @type SAML20DCE_NS: string
    @cvar SAML20DCE_PREFIX: SAML 2.0 DCE PAC Attribute Profile QName prefix.
    @type SAML20DCE_PREFIX: string
    @cvar SAML20X500_SCHEMA_LOCATION: SAML 2.0 X.500 Attribute Profile schema Id.
    @type SAML20X500_SCHEMA_LOCATION: string
    @cvar SAML20X500_NS: SAML 2.0 X.500 Attribute Profile XML Namespace.
    @type SAML20X500_NS: string
    @cvar SAML20X500_PREFIX: SAML 2.0 X.500 Attribute Profile QName prefix.
    @type SAML20X500_PREFIX: string
    @cvar SAML20XACML_SCHEMA_LOCATION: SAML 2.0 XACML Attribute Profile schema Id.
    @type SAML20XACML_SCHEMA_LOCATION: string
    @cvar SAML20XACML_NS: SAML 2.0 XACML Attribute Profile XML Namespace.
    @type SAML20XACML_NS: string
    @cvar SAML20XACML_PREFIX: SAML 2.0 XACML Attribute Profile QName prefix.
    @type SAML20XACML_PREFIX: string
    @cvar SAML2_ARTIFACT_BINDING_URI: URI for SAML 2 Artifact binding.
    @type SAML2_ARTIFACT_BINDING_URI: string
    @cvar SAML2_POST_BINDING_URI: URI for SAML 2 POST binding.
    @type SAML2_POST_BINDING_URI: string
    @cvar SAML2_POST_SIMPLE_SIGN_BINDING_URI: URI for SAML 2 POST-SimpleSign binding.
    @type SAML2_POST_SIMPLE_SIGN_BINDING_URI: string
    @cvar SAML2_REDIRECT_BINDING_URI: URI for SAML 2 HTTP redirect binding.
    @type SAML2_REDIRECT_BINDING_URI: string
    @cvar SAML2_SOAP11_BINDING_URI: URI for SAML 2 SOAP binding.
    @type SAML2_SOAP11_BINDING_URI: string
    '''
    
    # HTTP Constants
    
    # HTTP Request Method - POST.
    POST_METHOD = "POST"
    
    # HTTP Method - GET.
    GET_METHOD = "GET"
    
    # OpenSAML 2
    
    # Directory, on the classpath, schemas are located in.
    SCHEMA_DIR = "/schema/"
    
    #    Core XML
    
    # XML core schema system Id.
    XML_SCHEMA_LOCATION = SCHEMA_DIR + "xml.xsd"
    
    #  XML Signature schema Id.
    XMLSIG_SCHEMA_LOCATION = SCHEMA_DIR + "xmldsig-core-schema.xsd"
    
    # XML Encryption schema Id.
    XMLENC_SCHEMA_LOCATION = SCHEMA_DIR + "xenc-schema.xsd"

    
    #    SOAP
    
    #  SOAP 1.1 schema Id.
    SOAP11ENV_SCHEMA_LOCATION = SCHEMA_DIR + SCHEMA_DIR + "soap-envelope.xsd"
    
    #  SOAP 1.1 Envelope XML namespace.
    SOAP11ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
    
    #  SOAP 1.1 Envelope QName prefix.
    SOAP11ENV_PREFIX = "SOAP-ENV"
    
    #  Liberty PAOS XML Namespace.
    PAOS_NS = "urn:liberty:paos:2003-08"
    
    #  Liberty PAOS QName prefix.
    PAOS_PREFIX = "paos"
    
    #    SAML 1.X
    
    # SAML 1.0 Assertion schema system Id.
    SAML10_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-assertion-01.xsd"
    
    # SAML 1.1 Assertion schema system Id.
    SAML11_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-assertion-1.1.xsd"
    
    # SAML 1.X XML namespace.
    SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion"
    
    # SAML 1.0 Protocol schema system Id.
    SAML10P_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-protocol-01.xsd"
    
    # SAML 1.1 Protocol schema system Id.
    SAML11P_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-protocol-1.1.xsd"

    # SAML 1.X protocol XML namespace.
    SAML10P_NS = "urn:oasis:names:tc:SAML:1.0:protocol"
    
    # SAML 1.1 protocol XML namespace, used only in SAML 2 metadata protocol
    # SupportEnumeration.
    SAML11P_NS = "urn:oasis:names:tc:SAML:1.1:protocol"
    
    # SAML 1.X Protocol QName prefix.
    SAML1P_PREFIX = "samlp"

    # SAML 1.X Assertion QName prefix.
    SAML1_PREFIX = "saml"
    
    # SAML 1 Metadata extension XML namespace.
    SAML1MD_NS = "urn:oasis:names:tc:SAML:profiles:v1metadata"
    
    # SAML 1 Metadata extension schema system Id.
    SAML1MD_SCHEMA_LOCATION = SCHEMA_DIR + "sstc-saml1x-metadata.xsd"
    
    # SAML 1 Metadata extension namespace prefix.
    SAML1MD_PREFIX = "saml1md"
    
    # URI for SAML 1 Artifact binding.
    SAML1_ARTIFACT_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01"
    
    # URI for SAML 1 POST binding.
    SAML1_POST_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:profiles:browser-post"
    
    # URI for SAML 1 SOAP 1.1 binding.
    SAML1_SOAP11_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"
    
    #    SAML 2.0
    
    # SAML 2.0 Assertion schema Id.
    SAML20_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-assertion-2.0.xsd"
    
    # SAML 2.0 Assertion XML Namespace.
    SAML20_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    
    # SAML 2.0 Assertion QName prefix.
    SAML20_PREFIX ="saml"
    
    # SAML 2.0 Protocol schema Id.
    SAML20P_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-protocol-2.0.xsd"
    
    # SAML 2.0 Protocol XML Namespace.
    SAML20P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
    
    # SAML 2.0 Protocol QName prefix.
    SAML20P_PREFIX ="samlp"
    
    # SAML 2.0 Protocol Third-party extension schema Id.
    SAML20PTHRPTY_SCHEMA_LOCATION = SCHEMA_DIR + \
                                    "sstc-saml-protocol-ext-thirdparty.xsd"
    
    # SAML 2.0 Protocol XML Namespace.
    SAML20PTHRPTY_NS = "urn:oasis:names:tc:SAML:protocol:ext:third-party"
    
    # SAML 2.0 Protocol QName prefix.
    SAML20PTHRPTY_PREFIX ="thrpty"
    
    # SAML 2.0 Metadata schema Id.
    SAML20MD_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-metadata-2.0.xsd"
    
    # SAML 2.0 Metadata XML Namespace.
    SAML20MD_NS ="urn:oasis:names:tc:SAML:2.0:metadata"
    
    # SAML 2.0 Standalone Query Metadata extension XML namespace.
    SAML20MDQUERY_NS = "urn:oasis:names:tc:SAML:metadata:ext:query"
    
    # SAML 2.0 Standalone Query Metadata extension schema system Id.
    SAML20MDQUERY_SCHEMA_LOCATION = SCHEMA_DIR + \
                                    "sstc-saml-metadata-ext-query.xsd"
    
    # SAML 2.0 Standalone Query Metadata extension prefix.
    SAML20MDQUERY_PREFIX = "query"
    
    # SAML 2.0 Metadata QName prefix.
    SAML20MD_PREFIX = "md"
    
    # SAML 2.0 Authentication Context schema Id.
    SAML20AC_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-authn-context-2.0.xsd"
    
    # SAML 2.0 Authentication Context XML Namespace.
    SAML20AC_NS ="urn:oasis:names:tc:SAML:2.0:ac"
    
    # SAML 2.0 Authentication Context QName prefix.
    SAML20AC_PREFIX = "ac"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile schema Id.
    SAML20ECP_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-ecp-2.0.xsd"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile XML Namespace.
    SAML20ECP_NS = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile QName prefix.
    SAML20ECP_PREFIX = "ecp"
    
    # SAML 2.0 DCE PAC Attribute Profile schema Id.
    SAML20DCE_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-dce-2.0.xsd"
    
    # SAML 2.0 DCE PAC Attribute Profile XML Namespace.
    SAML20DCE_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE"
    
    # SAML 2.0 DCE PAC Attribute Profile QName prefix.
    SAML20DCE_PREFIX = "DCE"
    
    # SAML 2.0 X.500 Attribute Profile schema Id.
    SAML20X500_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-x500-2.0.xsd"
    
    # SAML 2.0 X.500 Attribute Profile XML Namespace.
    SAML20X500_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
    
    # SAML 2.0 X.500 Attribute Profile QName prefix.
    SAML20X500_PREFIX = "x500"
    
    # SAML 2.0 XACML Attribute Profile schema Id.
    SAML20XACML_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-xacml-2.0.xsd"
    
    # SAML 2.0 XACML Attribute Profile XML Namespace.
    SAML20XACML_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML"
    
    # SAML 2.0 XACML Attribute Profile QName prefix.
    SAML20XACML_PREFIX = "xacmlprof"
    
    # URI for SAML 2 Artifact binding.
    SAML2_ARTIFACT_BINDING_URI = \
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
    
    # URI for SAML 2 POST binding.
    SAML2_POST_BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    
    # URI for SAML 2 POST-SimpleSign binding.
    SAML2_POST_SIMPLE_SIGN_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
    
    # URI for SAML 2 HTTP redirect binding.
    SAML2_REDIRECT_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    
    # URI for SAML 2 SOAP binding.
    SAML2_SOAP11_BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
  
    
    # SAML 2.0 profile for XACML

    # SAML 2.0 profile for XACML assertion namespace
    SAML2_XACML_ASSERTION_NS = "urn:oasis:xacml:2.0:saml:assertion:schema:os"

    # SAML 2.0 profile for XACML assertion QName prefix
    SAML2_XACML_ASSERTION_PREFIX = "xacml-saml"

    # SAML 2.0 profile for XACML protocol namespace
    SAML2_XACML_PROTOCOL_NS = "urn:oasis:xacml:2.0:saml:protocol:schema:os"

    # SAML 2.0 profile for XACML protocol QName prefix
    SAML2_XACML_PROTOCOL_PREFIX = "xacml-samlp"

class QName(object):
    """XML Qualified Name
    @ivar __namespaceURI: the namespace the element is in
    @type __namespaceURI: basestring
    @ivar __localPart: the local name of the XML element 
    @type __localPart: basestring
    @ivar __prefix: the prefix for the given namespace
    @type __prefix: basestring
    """ 

    def __init__(self, namespaceURI, localPart, prefix):
        '''
        @param namespaceURI: the namespace the element is in
        @type namespaceURI: basestring
        @param localPart: the local name of the XML element 
        @type localPart: basestring
        @param prefix: the prefix for the given namespace
        @type prefix: basestring
        '''
        self.namespaceURI = namespaceURI
        self.localPart = localPart
        self.prefix = prefix
    
    def _getPrefix(self):
        """Get prefix
        @return: prefix
        @rtype: string
        """
        return self.__prefix

    def _setPrefix(self, value):
        """Set prefix
        @param value: prefix
        @type value: string
        @raise TypeError: invalid input value type
        """
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "prefix"; got %r' %
                            type(value))
        self.__prefix = value
    
    prefix = property(_getPrefix, _setPrefix, None, "Namespace Prefix")

    def _getLocalPart(self):
        """Get local part
        @return: local part
        @rtype: string
        """
        return self.__localPart
    
    def _setLocalPart(self, value):
        """Set local part
        @param value: local part
        @type value: string
        @raise TypeError: invalid input value type
        """
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "localPart"; got %r' %
                            type(value))
        self.__localPart = value
        
    localPart = property(_getLocalPart, _setLocalPart, None, "LocalPart")

    def _getNamespaceURI(self):
        """Get namespace URI
        @return: namespace URI
        @rtype: string
        """
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        """Set namespace URI
        @param value: namespace URI
        @type value: string
        @raise TypeError: invalid input value type
        """
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "namespaceURI"; got %r' %
                            type(value))
        self.__namespaceURI = value
  
    namespaceURI = property(_getNamespaceURI, _setNamespaceURI, None, 
                            "Namespace URI")

    def __eq__(self, qname):
        """Enable equality check for QName
        @type qname: saml.common.xml.QName
        @param qname: Qualified Name to compare with self 
        @return: True if input and this object match
        @rtype: bool
        @return: True if input and this object match
        @rtype: bool
        """
        if not isinstance(qname, QName):
            raise TypeError('Expecting %r; got %r' % (QName, type(qname)))
                            
        return (self.prefix, self.namespaceURI, self.localPart) == \
               (qname.prefix, qname.namespaceURI, qname.localPart)

    def __ne__(self, qname):
        """Enable equality check for QName
        @type qname: saml.common.xml.QName
        @param qname: Qualified Name to compare with self 
        @return: True if input and this object don't match
        @rtype: bool
        """
        return not self.__eq__(qname)
