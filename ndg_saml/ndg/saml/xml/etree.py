"""Implementation of SAML 2.0 for NDG Security - ElementTree module for
ElementTree representation of SAML objects

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
import logging
log = logging.getLogger(__name__)
import re

from ndg.saml import Config, importElementTree
ElementTree = importElementTree()

from ndg.saml.saml2.core import (SAMLObject, Attribute, AttributeStatement, 
                                 AuthnStatement, AuthzDecisionStatement, 
                                 Assertion, Conditions, AttributeValue, 
                                 AttributeQuery, AuthzDecisionQuery, Subject, 
                                 NameID, Issuer, Response, Status, StatusCode, 
                                 StatusMessage, StatusDetail, Advice, Action, 
                                 Evidence, DecisionType, XSStringAttributeValue) 
                             
from ndg.saml.common import SAMLVersion
from ndg.saml.common.xml import SAMLConstants
from ndg.saml.common.xml import QName as GenericQName
from ndg.saml.xml import XMLTypeParseError, UnknownAttrProfile
from ndg.saml.utils import SAMLDateTime

# Map of QName to ElementTree parsing class to be used in addition to those
# defined in this module.
_extensionElementTreeMap = {}

if Config.use_lxml:
    def makeEtreeElement(tag, ns_prefix, ns_uri, attrib={}, **extra):
        """Makes an ElementTree element handling namespaces in the way
        appropriate for the ElementTree implementation in use.
        """
        elem = ElementTree.Element(tag, {ns_prefix: ns_uri}, attrib, **extra)
        return elem
else:
    def makeEtreeElement(tag, ns_prefix, ns_uri, attrib={}, **extra):
        """Makes an ElementTree element handling namespaces in the way
         appropriate for the ElementTree implementation in use.
        """
        elem = ElementTree.Element(tag, attrib, **extra)
        ElementTree._namespace_map[ns_uri] = ns_prefix
        return elem

# Generic ElementTree Helper classes
class QName(ElementTree.QName):
    """Extend ElementTree implementation for improved attribute access support
    """ 

    # ElementTree tag is of the form {namespace}localPart.  getNs extracts the
    # namespace from within the brackets but if not found returns ''
    getNs = staticmethod(lambda tag: getattr(re.search('(?<=\{).+(?=\})', tag),
                                             'group', 
                                             str)())
                                             
    getLocalPart = staticmethod(lambda tag: tag.rsplit('}', 1)[-1])

    def __init__(self, input, tag=None, prefix=None):
        """
        @type input: basestring
        @param input: ElementTree style namespace URI + tag name -
        {namespace URI}tag - OR if tag keyword is set, the namespace URI alone
        @type tag: basestring / None
        @param tag: element tag name.  If None, input must contain the 
        namespace URI and tag name in the ElementTree form {namespace URI}tag.
        @type prefix: basestring / None
        @param prefix: namespace prefix
        """
        
        ElementTree.QName.__init__(self, input, tag=tag)
        
        if tag:
            self.namespaceURI = input
            self.localPart = tag
        else:
            # No tag provided namespace and localPart of QN must be parsed from
            # the namespace
            self.namespaceURI = QName.getNs(input)
            self.localPart = QName.getLocalPart(input)
            
        self.prefix = prefix
    
    def _getPrefix(self):
        """@return: NS prefix
        @rtype: basestring
        """
        return self.__prefix

    def _setPrefix(self, value):
        """@param value: NS prefix
        @type value: basestring
        """
        self.__prefix = value
    
    prefix = property(_getPrefix, _setPrefix, None, "Prefix")

    def _getLocalPart(self):
        """@return: NS local name
        @rtype: basestring
        """
        return self.__localPart
    
    def _setLocalPart(self, value):
        """@param value: NS local name
        @type value: basestring
        """
        self.__localPart = value
        
    localPart = property(_getLocalPart, _setLocalPart, None, "LocalPart")

    def _getNamespaceURI(self):
        """@return: NS URI
        @rtype: basestring
        """
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        """@param value: NS URI
        @type value: basestring
        """
        self.__namespaceURI = value
  
    namespaceURI = property(_getNamespaceURI, _setNamespaceURI, None, 
                            "Namespace URI'")

    def __eq__(self, qname):
        """Enable equality check for QName.  Note that prefixes don't need to
        match
        
        @type qname: ndg.security.common.utils.etree.QName
        @param qname: Qualified Name to compare with self 
        
        @return: True if the qualified names match, False otherwise
        @rtype: bool
        """
        if not isinstance(qname, QName):
            raise TypeError('Expecting %r; got %r' % (QName, type(qname)))
                   
        # Nb. prefixes don't need to agree!         
        return (self.namespaceURI, self.localPart) == \
               (qname.namespaceURI, qname.localPart)

    def __ne__(self, qname):
        """Enable equality check for QName.  Note that prefixes don't need to
        match
        
        @type qname: ndg.security.common.utils.etree.QName
        @param qname: Qualified Name to compare with self 
        @return: True if the qualified names don't match, False otherwise
        @rtype: bool
        """
        return not self.__eq__(qname)

    @classmethod
    def fromGeneric(cls, genericQName):
        '''Cast the generic QName type in ndg.saml.common.xml to this
        ElementTree specific implementation
        
        @param genericQName: SAML core qualified name type
        @type genericQName: ndg.saml.common.xml.QName
        @return: ElementTree specific qualified name type
        @rtype: ndg.saml.xml.etree.QName
        '''
        if not isinstance(genericQName, GenericQName):
            raise TypeError("Expecting %r for QName, got %r" % (GenericQName,
                                                        type(genericQName)))
            
        qname = cls(genericQName.namespaceURI, 
                    tag=genericQName.localPart,
                    prefix=genericQName.prefix)
        return qname
    
    
def prettyPrint(*arg, **kw):
    '''Lightweight pretty printing of ElementTree elements.  This function
    wraps the PrettyPrint class
    
    @param arg: arguments to pretty print function
    @type arg: tuple
    @param kw: keyword arguments to pretty print function
    @type kw: dict
    '''
    
    # Keep track of namespace declarations made so they're not repeated
    declaredNss = []
    if not Config.use_lxml:
        mappedPrefixes = dict.fromkeys(ElementTree._namespace_map.values(), True)
        namespace_map_backup = ElementTree._namespace_map.copy()
    else:
        mappedPrefixes = {}

    _prettyPrint = _PrettyPrint(declaredNss, mappedPrefixes)
    result = _prettyPrint(*arg, **kw)

    if not Config.use_lxml:
        ElementTree._namespace_map = namespace_map_backup

    return result


class _PrettyPrint(object):
    '''Class for lightweight pretty printing of ElementTree elements'''
    MAX_NS_TRIES = 256
    def __init__(self, declaredNss, mappedPrefixes):
        """
        @param declaredNss: declared namespaces
        @type declaredNss: iterable of string elements
        @param mappedPrefixes: map of namespace URIs to prefixes
        @type mappedPrefixes: map of string to string
        """
        self.declaredNss = declaredNss
        self.mappedPrefixes = mappedPrefixes
    
    @staticmethod
    def estrip(elem):
        '''Utility to remove unwanted leading and trailing whitespace 
        
        @param elem: ElementTree element
        @type elem: ElementTree.Element
        @return: element content with whitespace removed
        @rtype: basestring'''
        if elem is None:
            return ''
        else:
            # just in case the elem is another simple type - e.g. int - 
            # wrapper it as a string
            return str(elem).strip()
        
    def __call__(self, elem, indent='', html=0, space=' '*4):
        '''Most of the work done in this wrapped function - wrapped so that
        state can be maintained for declared namespace declarations during
        recursive calls using "declaredNss" above
        
        @param elem: ElementTree element
        @type elem: ElementTree.Element
        @param indent: set indent for output
        @type indent: basestring
        @param space: set output spacing
        @type space: basestring 
        @return: pretty print format for doc
        @rtype: basestring       
        '''  
        strAttribs = []
        for attr, attrVal in elem.attrib.items():
            nsDeclaration = ''
            
            attrNamespace = QName.getNs(attr)
            if attrNamespace:
                nsPrefix = self._getNamespacePrefix(elem, attrNamespace)
                
                attr = "%s:%s" % (nsPrefix, QName.getLocalPart(attr))
                
                if attrNamespace not in self.declaredNss:
                    nsDeclaration = ' xmlns:%s="%s"' % (nsPrefix,attrNamespace)
                    self.declaredNss.append(attrNamespace)
                
            strAttribs.append('%s %s="%s"' % (nsDeclaration, attr, attrVal))
            
        strAttrib = ''.join(strAttribs)
        
        namespace = QName.getNs(elem.tag)
        nsPrefix = self._getNamespacePrefix(elem, namespace)
            
        tag = "%s:%s" % (nsPrefix, QName.getLocalPart(elem.tag))
        
        # Put in namespace declaration if one doesn't already exist
        # FIXME: namespace declaration handling is wrong for handling child
        # element scope
        if namespace in self.declaredNss:
            nsDeclaration = ''
        else:
            nsDeclaration = ' xmlns:%s="%s"' % (nsPrefix, namespace)
            self.declaredNss.append(namespace)
            
        result = '%s<%s%s%s>%s' % (indent, tag, nsDeclaration, strAttrib, 
                                   _PrettyPrint.estrip(elem.text))
        
        children = len(elem)
        if children:
            for child in elem:
                declaredNss = self.declaredNss[:]
                _prettyPrint = _PrettyPrint(declaredNss, self.mappedPrefixes)
                result += '\n'+ _prettyPrint(child, indent=indent+space) 
                
            result += '\n%s%s</%s>' % (indent,
                                     _PrettyPrint.estrip(child.tail),
                                     tag)
        else:
            result += '</%s>' % tag
            
        return result

    if Config.use_lxml:
        def _getNamespacePrefix(self, elem, namespace):
            for nsPrefix, ns in elem.nsmap.iteritems():
                if ns == namespace:
                    return nsPrefix
            raise KeyError('prettyPrint: missing namespace "%s" for '
                               'elem.nsmap' % namespace)
    else:
        def _getNamespacePrefix(self, elem, namespace):
            nsPrefix = self._allocNsPrefix(namespace)
            if nsPrefix is None:
                raise KeyError('prettyPrint: missing namespace "%s" for '
                               'ElementTree._namespace_map' % namespace)
            return nsPrefix

        def _allocNsPrefix(self, nsURI):
            """Allocate a namespace prefix if one is not already set for the given
            Namespace URI
            """
            nsPrefix = ElementTree._namespace_map.get(nsURI)
            if nsPrefix is not None:
                return nsPrefix

            for i in range(self.__class__.MAX_NS_TRIES):
                nsPrefix = "ns%d" % i
                if nsPrefix not in self.mappedPrefixes:
                    ElementTree._namespace_map[nsURI] = nsPrefix
                    self.mappedPrefixes[nsPrefix] = True
                    break

            if nsURI not in ElementTree._namespace_map:                            
                raise KeyError('prettyPrint: error adding namespace '
                               '"%s" to ElementTree._namespace_map' % 
                               nsURI)   

            return nsPrefix

# ElementTree SAML wrapper classes
class ConditionsElementTree(Conditions):
    """ElementTree based XML representation of Conditions class
    """
    
    @classmethod
    def toXML(cls, conditions):
        """Make a tree of a XML elements based on the assertion conditions
        
        @type conditions: saml.saml2.core.Conditions
        @param conditions: Assertion conditions to be represented as an 
        ElementTree Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        if not isinstance(conditions, Conditions):
            raise TypeError("Expecting %r type got: %r" % (Conditions,
                                                           conditions))
        
        notBeforeStr = SAMLDateTime.toString(conditions.notBefore)
        notOnOrAfterStr = SAMLDateTime.toString(conditions.notOnOrAfter)
        attrib = {
            cls.NOT_BEFORE_ATTRIB_NAME: notBeforeStr,
            cls.NOT_ON_OR_AFTER_ATTRIB_NAME: notOnOrAfterStr,
        }
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)

        for condition in conditions.conditions:
            raise NotImplementedError("Conditions list creation is not "
                                      "implemented")
                
        return elem
    
    @classmethod
    def fromXML(cls, elem):
        """Parse an ElementTree SAML Conditions element into an
        Conditions object
        
        @type elem: ElementTree.Element
        @param elem: ElementTree element containing the conditions
        @rtype: saml.saml2.core.Conditions
        @return: Conditions object
        """
        
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        
        if len(elem) > 0:
            raise NotImplementedError("Conditions list parsing is not "
                                      "implemented")

        conditions = Conditions()
        notBefore = elem.attrib.get(Conditions.NOT_BEFORE_ATTRIB_NAME)
        if notBefore is not None:
            conditions.notBefore = SAMLDateTime.fromString(notBefore)
            
        notOnOrAfter = elem.attrib.get(Conditions.NOT_ON_OR_AFTER_ATTRIB_NAME)
        if notBefore is not None:
            conditions.notOnOrAfter = SAMLDateTime.fromString(notOnOrAfter)
            
        return conditions                
        
               
class AssertionElementTree(Assertion):
    """ElementTree based XML representation of Assertion class
    """
    
    @classmethod
    def toXML(cls, assertion, **attributeValueElementTreeFactoryKw):
        """Make a tree of a XML elements based on the assertion
        
        @type assertion: saml.saml2.core.Assertion
        @param assertion: Assertion to be represented as an ElementTree Element
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        
        if not isinstance(assertion, Assertion):
            raise TypeError("Expecting %r type got: %r"%(Assertion, assertion))
        
        issueInstant = SAMLDateTime.toString(assertion.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: assertion.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(assertion.version)
        }
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)
        
        if assertion.issuer is not None:
            issuerElem = IssuerElementTree.toXML(assertion.issuer)
            elem.append(issuerElem)
        
        if assertion.subject is not None:
            subjectElem = SubjectElementTree.toXML(assertion.subject)
            elem.append(subjectElem)

        if assertion.advice:
            raise NotImplementedError("Assertion Advice creation is not "
                                      "implemented")

        if assertion.conditions is not None:
            conditionsElem = ConditionsElementTree.toXML(assertion.conditions)
            elem.append(conditionsElem)
            
        for statement in assertion.statements:
            qname = statement.qname
            etreeImpl = _getElementTreeImplementationForQName(qname)
            if etreeImpl is None:
                raise NotImplementedError("No ElementTree implementation for "
                                          "QName {%s}%s" %
                                          (qname.namespaceURI, qname.localPart))
            statementElem = etreeImpl.toXML(statement)
            elem.append(statementElem)
        
        for authnStatement in assertion.authnStatements:
            raise NotImplementedError("Assertion Authentication Statement "
                                      "creation is not implemented")
        
        for authzDecisionStatement in assertion.authzDecisionStatements:
            authzDecisionStatementElem = \
                AuthzDecisionStatementElementTree.toXML(authzDecisionStatement)
            elem.append(authzDecisionStatementElem)
            
        for attributeStatement in assertion.attributeStatements:
            attributeStatementElem = AttributeStatementElementTree.toXML(
                                        attributeStatement,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeStatementElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem, **attributeValueElementTreeFactoryKw):
        """Parse an ElementTree representation of an Assertion into an
        Assertion object
        
        @type elem: ElementTree.Element
        @param elem: ElementTree element containing the assertion
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        @rtype: saml.saml2.core.Assertion
        @return: Assertion object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.VERSION_ATTRIB_NAME,
                              cls.ISSUE_INSTANT_ATTRIB_NAME,
                              cls.ID_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                          'element' %
                                          (attributeName,
                                           cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        assertion = cls()
        assertion.version = SAMLVersion(attributeValues[0])
        if assertion.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(assertion.version)))
            
        assertion.issueInstant = SAMLDateTime.fromString(attributeValues[1])
        assertion.id = attributeValues[2]
        
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)

            statementElementTree = _getElementTreeImplementationForQName(QName(childElem.tag))

            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                assertion.issuer = IssuerElementTree.fromXML(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse subject
                assertion.subject = SubjectElementTree.fromXML(childElem)
                
            elif localName == Advice.DEFAULT_ELEMENT_LOCAL_NAME:
                raise NotImplementedError("Assertion Advice parsing is not "
                                          "implemented")
                
            elif localName == Conditions.DEFAULT_ELEMENT_LOCAL_NAME:
                assertion.conditions = ConditionsElementTree.fromXML(childElem)

            elif statementElementTree is not None:
                statement = statementElementTree.fromXML(childElem)
                assertion.statements.append(statement)

            elif localName == AuthnStatement.DEFAULT_ELEMENT_LOCAL_NAME:
                raise NotImplementedError("Assertion Authentication Statement "
                                          "parsing is not implemented")
        
            elif localName == AuthzDecisionStatement.DEFAULT_ELEMENT_LOCAL_NAME:
                authzDecisionStatement = \
                    AuthzDecisionStatementElementTree.fromXML(childElem)
                assertion.authzDecisionStatements.append(authzDecisionStatement)
            
            elif localName == AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME:
                attributeStatement = AttributeStatementElementTree.fromXML(
                                        childElem,
                                        **attributeValueElementTreeFactoryKw)
                assertion.attributeStatements.append(attributeStatement)
            else:
                raise XMLTypeParseError('Assertion child element name "%s" '
                                        'not recognised' % localName)
        
        return assertion

  
class AttributeStatementElementTree(AttributeStatement):
    """ElementTree XML representation of AttributeStatement"""
    
    @classmethod
    def toXML(cls, attributeStatement, **attributeValueElementTreeFactoryKw):
        """Make a tree of a XML elements based on the attribute statement
        
        @type attributeStatement: saml.saml2.core.AttributeStatement
        @param attributeStatement: Attribute Statement to be represented as an 
        ElementTree Element
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        if not isinstance(attributeStatement, AttributeStatement):
            raise TypeError("Expecting %r type got: %r" % (AttributeStatement, 
                                                           attributeStatement))
            
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))  
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI)

        for attribute in attributeStatement.attributes:
            # Factory enables support for multiple attribute types
            attributeElem = AttributeElementTree.toXML(attribute,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeElem)
        
        return elem
    
    @classmethod
    def fromXML(cls, elem, **attributeValueElementTreeFactoryKw):
        """Parse an ElementTree SAML AttributeStatement element into an
        AttributeStatement object
        
        @type elem: ElementTree.Element
        @param elem: ElementTree element containing the AttributeStatement
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: saml.saml2.core.AttributeStatement
        @return: Attribute Statement
        """
        
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        
        attributeStatement = AttributeStatement()

        for childElem in elem:
            # Factory enables support for multiple attribute types
            attribute = AttributeElementTree.fromXML(childElem,
                                        **attributeValueElementTreeFactoryKw)
            attributeStatement.attributes.append(attribute)
        
        return attributeStatement

  
class AuthzDecisionStatementElementTree(AuthzDecisionStatement):
    """ElementTree XML representation of AuthzDecisionStatement"""
    
    @classmethod
    def toXML(cls, authzDecisionStatement):
        """Make a tree of a XML elements based on the authzDecision statement
        
        @type authzDecisionStatement: saml.saml2.core.AuthzDecisionStatement
        @param authzDecisionStatement: AuthzDecision Statement to be represented
        as an ElementTree Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        if not isinstance(authzDecisionStatement, AuthzDecisionStatement):
            raise TypeError("Expecting %r type got: %r" % 
                            (AuthzDecisionStatement, authzDecisionStatement))
          
        if not authzDecisionStatement.resource:
            raise AttributeError("Resource for AuthzDecisionStatement is not "
                                 "set")
              
        attrib = {
            cls.DECISION_ATTRIB_NAME: str(authzDecisionStatement.decision),
            cls.RESOURCE_ATTRIB_NAME: authzDecisionStatement.resource
        }
            
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))  
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)

        for action in authzDecisionStatement.actions:
            # Factory enables support for multiple authzDecision types
            actionElem = ActionElementTree.toXML(action)
            elem.append(actionElem)
        
        if (authzDecisionStatement.evidence and 
            len(authzDecisionStatement.evidence.values) > 0):
            raise NotImplementedError("authzDecisionStatementElementTree does "
                                      "not currently support the Evidence type")
            
        return elem
    
    @classmethod
    def fromXML(cls, elem):
        """Parse an ElementTree SAML AuthzDecisionStatement element into an
        AuthzDecisionStatement object
        
        @type elem: ElementTree.Element
        @param elem: ElementTree element containing the AuthzDecisionStatement
        @rtype: saml.saml2.core.AuthzDecisionStatement
        @return: AuthzDecision Statement"""
        
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.DECISION_ATTRIB_NAME,
                              cls.RESOURCE_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                 'element' %
                                 (attributeName,
                                  cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        authzDecisionStatement = AuthzDecisionStatement()
        authzDecisionStatement.decision = DecisionType(attributeValues[0])
        authzDecisionStatement.resource = attributeValues[1]

        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            
            if localName == Action.DEFAULT_ELEMENT_LOCAL_NAME:
                action = ActionElementTree.fromXML(childElem)
                authzDecisionStatement.actions.append(action)
                
            elif localName == Evidence.DEFAULT_ELEMENT_LOCAL_NAME:
                raise NotImplementedError("XML parse of %s element is not "
                                          "implemented" %
                                          Evidence.DEFAULT_ELEMENT_LOCAL_NAME)
            else:
                raise XMLTypeParseError("AuthzDecisionStatement child element "
                                        "name %r not recognised" % localName)
        
        return authzDecisionStatement


class AttributeElementTree(Attribute):
    """ElementTree XML representation of SAML Attribute object.  Extend
    to make Attribute types""" 

    @classmethod
    def toXML(cls, attribute, **attributeValueElementTreeFactoryKw):
        """Make a tree of a XML elements based on the Attribute
        
        @type attribute: saml.saml2.core.Attribute
        @param attribute: Attribute to be represented as an ElementTree Element
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        if not isinstance(attribute, Attribute):
            raise TypeError("Expecting %r type got: %r"%(Attribute, attribute))
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))    
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI)
        
        if attribute.friendlyName:
            elem.set(cls.FRIENDLY_NAME_ATTRIB_NAME, attribute.friendlyName) 
             
        if attribute.name:
            elem.set(cls.NAME_ATTRIB_NAME, attribute.name)
        
        if attribute.nameFormat:
            elem.set(cls.NAME_FORMAT_ATTRIB_NAME, attribute.nameFormat)

        for attributeValue in attribute.attributeValues:
            factory = AttributeValueElementTreeFactory(
                                        **attributeValueElementTreeFactoryKw)
            
            attributeValueElementTree = factory(attributeValue)
            
            attributeValueElem = attributeValueElementTree.toXML(attributeValue)
            elem.append(attributeValueElem)
            
        return elem
 
    @classmethod
    def fromXML(cls, elem, **attributeValueElementTreeFactoryKw):
        """Parse ElementTree element into a SAML Attribute object
        
        @type elem: ElementTree.Element
        @param elem: Attribute as ElementTree XML element
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: saml.saml2.core.Attribute
        @return: SAML Attribute
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        attribute = Attribute()
            
        # Name is mandatory in the schema
        name = elem.attrib.get(cls.NAME_ATTRIB_NAME)
        if name is None:
            raise XMLTypeParseError('No "%s" attribute found in the "%s" '
                                    'element' %
                                    (cls.NAME_ATTRIB_NAME,
                                     cls.DEFAULT_ELEMENT_LOCAL_NAME))
        attribute.name = name
            
        friendlyName = elem.attrib.get(cls.FRIENDLY_NAME_ATTRIB_NAME)
        if friendlyName is not None:
            attribute.friendlyName = friendlyName
            
        nameFormat = elem.attrib.get(cls.NAME_FORMAT_ATTRIB_NAME)    
        if nameFormat is not None:
            attribute.nameFormat = nameFormat
        
        # Factory to handle the different Attribute Value types
        factory = AttributeValueElementTreeFactory(
                                        **attributeValueElementTreeFactoryKw)

        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName != AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME:
                raise XMLTypeParseError('Expecting "%s" element; found "%s"'%
                                    (AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME,
                                     localName))
                            
            attributeValueElementTreeClass = factory(childElem)
            attributeValue = attributeValueElementTreeClass.fromXML(childElem)
            attribute.attributeValues.append(attributeValue)
        
        return attribute
        
    
class AttributeValueElementTreeBase(AttributeValue):
    """Base class ElementTree XML representation of SAML Attribute Value""" 
    
    @classmethod
    def toXML(cls, attributeValue):
        """Make a tree of a XML elements based on the Attribute value
        
        @type attributeValue: saml.saml2.core.AttributeValue
        @param attributeValue: Assertion to be represented as an ElementTree 
        Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        if not isinstance(attributeValue, AttributeValue):
            raise TypeError("Expecting %r type got: %r" % (AttributeValue, 
                                                           attributeValue))
            
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))   
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI)

        return elem


class XSStringAttributeValueElementTree(AttributeValueElementTreeBase,
                                        XSStringAttributeValue):
    """ElementTree XML representation of SAML String type Attribute Value""" 
    
    @classmethod
    def toXML(cls, attributeValue):
        """Create an XML representation of the input SAML Attribute Value 
        
        @type attributeValue: saml.saml2.core.XSStringAttributeValue
        @param attributeValue: xs:string to be represented as an ElementTree 
        Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        elem = AttributeValueElementTreeBase.toXML(attributeValue)
        
        if not isinstance(attributeValue, XSStringAttributeValue):
            raise TypeError("Expecting %r type got: %r" % 
                            (XSStringAttributeValue, attributeValue)) 
        
        if Config.use_lxml:
            elem.set(("{%s}%s" % (SAMLConstants.XSI_NS, 'type')),
                     "%s:%s" % (SAMLConstants.XSD_PREFIX, 
                                cls.TYPE_LOCAL_NAME))
        else:
            # Have to explicitly add namespace declaration here rather use 
            # ElementTree._namespace_map because the prefixes are used for 
            # attributes not element names
            elem.set("%s:%s" % (SAMLConstants.XMLNS_PREFIX, 
                                SAMLConstants.XSD_PREFIX),
                     SAMLConstants.XSD_NS)
                                       
            elem.set("%s:%s" % (SAMLConstants.XMLNS_PREFIX, 
                                SAMLConstants.XSI_PREFIX),
                     SAMLConstants.XSI_NS)
            
            elem.set("%s:%s" % (SAMLConstants.XSI_PREFIX, 'type'), 
                     "%s:%s" % (SAMLConstants.XSD_PREFIX, 
                                cls.TYPE_LOCAL_NAME))

        elem.text = attributeValue.value

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree xs:string element into a SAML 
        XSStringAttributeValue object
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: saml.saml2.core.AttributeValue
        @return: SAML Attribute value
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Parse the attribute type checking that it is set to the expected 
        # string type
        typeQName = QName(SAMLConstants.XSI_NS, tag='type')
        
        typeValue = elem.attrib.get(str(typeQName), '')
        typeValueLocalName = typeValue.split(':')[-1]
        if typeValueLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLTypeParseError('Expecting "%s" type; got "%s"' %
                                      (cls.TYPE_LOCAL_NAME,
                                       typeValueLocalName))
        
        # Update namespace map as an XSI type has been referenced.  This will
        # ensure the correct prefix is applied if it is re-serialised.
        if not Config.use_lxml:
            ElementTree._namespace_map[SAMLConstants.XSI_NS
                                       ] = SAMLConstants.XSI_PREFIX
                                      
        attributeValue = XSStringAttributeValue()
        if elem.text is not None:
            attributeValue.value = elem.text.strip()

        return attributeValue


class AttributeValueElementTreeFactory(object):
    """Class factory for AttributeValue ElementTree classes.  These classes are
    used to represent SAML Attribute value types
    
    @type toXMLTypeMap: dict
    @cvar toXMLTypeMap: mapping between SAML AttributeValue class and its 
    ElementTree handler class
    @type toSAMLTypeMap: dict
    @cvar toSAMLTypeMap: mapping between SAML AttributeValue string identifier 
    and its ElementTree handler class
    """
    toXMLTypeMap = {
        XSStringAttributeValue: XSStringAttributeValueElementTree
    }

    def xsstringMatch(elem):
        """Match function for xs:string type attribute.
        
        @type elem: ElementTree.Element
        @param elem: Attribute Value element to be checked
        @rtype: XSStringAttributeValueElementTree/None
        @return: Parsing class if this element is an xs:string Attribute Value,
        None otherwise.
        """
        # Iterate through the attributes searching for a type attribute set to
        # xs:string
        for attribName, attribVal in elem.attrib.items():
            qname = QName(attribName)
            if qname.localPart == "type":
                typeLocalName = attribVal.split(':')[-1]
                
                if typeLocalName == XSStringAttributeValue.TYPE_LOCAL_NAME:
                    return XSStringAttributeValueElementTree
                else:
                    return None
                
        # No type attribute was found for this Attribute element
        return None
        
    toSAMLTypeMap = [xsstringMatch]
    xsstringMatch = staticmethod(toSAMLTypeMap[0])
   
    def __init__(self, customToXMLTypeMap=None, customToSAMLTypeMap=None): 
        """Set-up a SAML class to ElementTree mapping
        
        @type customToXMLTypeMap: dict
        @param customToXMLTypeMap: mapping for custom SAML AttributeValue 
        classes to their respective ElementTree based representations.  This 
        appends to self.__toXMLTypeMap
        @type customToSAMLTypeMap: dict
        @param customToSAMLTypeMap: string ID based mapping for custom SAML 
        AttributeValue classes to their respective ElementTree based 
        representations.  As with customToXMLTypeMap, this appends to
        to the respective self.__toSAMLTypeMap
        """
        if customToXMLTypeMap is None:
            customToXMLTypeMap = {}
            
        if customToSAMLTypeMap is None:
            customToSAMLTypeMap = []
            
        self.__toXMLTypeMap = AttributeValueElementTreeFactory.toXMLTypeMap
        if not isinstance(customToXMLTypeMap, dict):
            raise TypeError('Expecting dict type for "customToXMLTypeMap"')

        for samlClass, etreeClass in customToXMLTypeMap.items(): 
            if not issubclass(samlClass, AttributeValue):
                raise TypeError("Input custom class must be derived from %r, "
                                "got %r instead" % (Attribute, samlClass))
                
            self.__toXMLTypeMap[samlClass] = etreeClass

        if not isinstance(customToSAMLTypeMap, (list, tuple)):
            raise TypeError('Expecting list or tuple type for '
                            '"customToSAMLTypeMap"')
        
        self.__toSAMLTypeMap = AttributeValueElementTreeFactory.toSAMLTypeMap[:]
        for func in customToSAMLTypeMap:
            if not callable(func):
                raise TypeError('"customToSAMLTypeMap" items must be callable')
            
        self.__toSAMLTypeMap += customToSAMLTypeMap

    def __call__(self, input):
        """Create an ElementTree object based on the Attribute class type
        passed in
        
        @type input: saml.saml2.core.AttributeValue or basestring
        @param input: pass an AttributeValue derived type or a string.  If
        an AttributeValue type, then self.__toXMLTypeMap is checked for a 
        matching AttributeValue class entry, if a string is passed, 
        self.__toSAMLTypeMap is checked for a matching string ID.  In both 
        cases, if a match is found an ElementTree class is returned which can 
        render or parse the relevant AttributeValue class
        """
        if isinstance(input, AttributeValue):
            XMLTypeClass = self.__toXMLTypeMap.get(input.__class__)
            if XMLTypeClass is None:
                raise UnknownAttrProfile("no matching XMLType class "
                                         "representation for class %r" % 
                                         input.__class__)
                
        elif ElementTree.iselement(input):
            XMLTypeClasses = []
            for matchFunc in self.__toSAMLTypeMap:
                cls = matchFunc(input)
                if cls is None:
                    continue
                elif issubclass(cls, AttributeValue):
                    XMLTypeClasses.append(cls)
                else:
                    raise TypeError("Expecting AttributeValue derived type "
                                    "for XML class; got %r" % cls)
            
            nXMLTypeClasses = len(XMLTypeClasses)
            if nXMLTypeClasses == 0:
                raise UnknownAttrProfile("no matching XMLType class "
                                         "representation for SAML "
                                         "AttributeValue type %r" % input)
            elif nXMLTypeClasses > 1:
                raise TypeError("Multiple XMLType classes %r matched for "
                                "for SAML AttributeValue type %r" % 
                                (XMLTypeClasses, input)) 
                   
            XMLTypeClass = XMLTypeClasses[0]            
        else:
            raise TypeError("Expecting %r class got %r" % (AttributeValue, 
                                                           type(input)))
        return XMLTypeClass
    

class IssuerElementTree(Issuer):
    """Represent a SAML Issuer element in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, issuer):
        """Create an XML representation of the input SAML issuer object
        
        @type issuer: saml.saml2.core.Issuer
        @param issuer: Assertion object
        @rtype: ElementTree.Element
        @return: ElementTree element containing the assertion
        """
        if not isinstance(issuer, Issuer):
            raise TypeError("Expecting %r class got %r" % (Issuer, 
                                                           type(issuer)))
            
        # Issuer format may be omitted from a response: saml-profiles-2.0-os,
        # Section 4.1.4.2
        attrib = {}
        if issuer.format is not None:
            attrib[cls.FORMAT_ATTRIB_NAME] = issuer.format
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, issuer.qname.prefix,
                                issuer.qname.namespaceURI,
                                **attrib)
                                   
        elem.text = issuer.value

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML Issuer instance
        
        @type elem: ElementTree.Element
        @param elem: ElementTree element containing the assertion
        @rtype: saml.saml2.core.Issuer
        @return: Assertion object"""
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" element found' %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        issuerFormat = elem.attrib.get(cls.FORMAT_ATTRIB_NAME)
        issuer = Issuer()
        
        # Issuer format may be omitted from a response: saml-profiles-2.0-os,
        # Section 4.1.4.2
        if issuerFormat is not None:
            issuer.format = issuerFormat
        
        if elem.text is None:
            raise XMLTypeParseError('No SAML issuer value set')
        
        issuer.value = elem.text.strip() 
        
        return issuer

        
class NameIdElementTree(NameID):
    """Represent a SAML Name Identifier in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, nameID):
        """Create an XML representation of the input SAML Name Identifier
        object
        @type nameID: saml.saml2.core.NameID
        @param nameID: SAML name ID
        @rtype: ElementTree.Element
        @return: Name ID as ElementTree XML element
        """
        
        if not isinstance(nameID, NameID):
            raise TypeError("Expecting %r class got %r" % (NameID, 
                                                           type(nameID)))
        attrib = {
            cls.FORMAT_ATTRIB_NAME: nameID.format
        }
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, nameID.qname.prefix,
                                nameID.qname.namespaceURI,
                                **attrib)
        
        elem.text = nameID.value

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML NameID object
        
        @type elem: ElementTree.Element
        @param elem: Name ID as ElementTree XML element
        @rtype: saml.saml2.core.NameID
        @return: SAML Name ID
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        format = elem.attrib.get(cls.FORMAT_ATTRIB_NAME)
        if format is None:
            raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                    'element' %
                                    (cls.FORMAT_ATTRIB_NAME,
                                     cls.DEFAULT_ELEMENT_LOCAL_NAME))
        nameID = NameID()
        nameID.format = format
        if elem.text is None:
            nameID.value = ''
        else:
            nameID.value = elem.text.strip() 
        
        return nameID


class SubjectElementTree(Subject):
    """Represent a SAML Subject in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, subject):
        """Create an XML representation of the input SAML subject object
        @type subject: saml.saml2.core.Subject
        @param subject: SAML subject
        @rtype: ElementTree.Element
        @return: subject as ElementTree XML element
        """
        if not isinstance(subject, Subject):
            raise TypeError("Expecting %r class got %r" % (Subject, 
                                                           type(subject)))
            
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))  
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI)

        nameIdElem = NameIdElementTree.toXML(subject.nameID)
        elem.append(nameIdElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML Subject object
        
        @type elem: ElementTree.Element
        @param elem: subject as ElementTree XML element
        @rtype: saml.saml2.core.Subject
        @return: SAML subject
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        if len(elem) != 1:
            raise XMLTypeParseError("Expecting single Name ID child element "
                                      "for SAML Subject element")
            
        subject = Subject()
        subject.nameID = NameIdElementTree.fromXML(elem[0])
        
        return subject

        
class StatusCodeElementTree(StatusCode):
    """Represent a SAML Status Code in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, statusCode):
        """Create an XML representation of the input SAML Name Status Code
        
        @type statusCode: saml.saml2.core.StatusCode
        @param statusCode: SAML Status Code
        @rtype: ElementTree.Element
        @return: Status Code as ElementTree XML element
        """
        
        if not isinstance(statusCode, StatusCode):
            raise TypeError("Expecting %r class got %r" % (StatusCode, 
                                                           type(statusCode)))
            
        attrib = {
            cls.VALUE_ATTRIB_NAME: statusCode.value
        }
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, statusCode.qname.prefix,
                                statusCode.qname.namespaceURI,
                                **attrib)

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML StatusCode object
        
        @type elem: ElementTree.Element
        @param elem: Status Code as ElementTree XML element
        @rtype: saml.saml2.core.StatusCode
        @return: SAML Status Code
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" element found' %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        statusCode = StatusCode()
            
        value = elem.attrib.get(cls.VALUE_ATTRIB_NAME)
        if value is None:
            raise XMLTypeParseError('No "%s" attribute found in "%s" element' %
                                    (cls.VALUE_ATTRIB_NAME,
                                     cls.DEFAULT_ELEMENT_LOCAL_NAME))
        statusCode.value = value
        
        return statusCode

        
class StatusMessageElementTree(StatusMessage):
    """Represent a SAML Status Message in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, statusMessage):
        """Create an XML representation of the input SAML Name Status Message
        
        @type statusMessage: saml.saml2.core.StatusMessage
        @param statusMessage: SAML Status Message
        @rtype: ElementTree.Element
        @return: Status Code as ElementTree XML element
        """
        
        if not isinstance(statusMessage, StatusMessage):
            raise TypeError("Expecting %r class got %r" % (StatusMessage, 
                                                           type(statusMessage)))
            
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, statusMessage.qname.prefix,
                                statusMessage.qname.namespaceURI)
        
        elem.text = statusMessage.value

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML StatusMessage object
        
        @type elem: ElementTree.Element
        @param elem: Status Code as ElementTree XML element
        @rtype: saml.saml2.core.StatusMessage
        @return: SAML Status Message
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" element found' %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        statusMessage = StatusMessage()
        if elem.text is not None:
            statusMessage.value = elem.text.strip() 
        
        return statusMessage


class StatusElementTree(Status):
    """Represent a SAML Status in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, status):
        """Create an XML representation of the input SAML subject object
        @type status: saml.saml2.core.Status
        @param status: SAML subject
        @rtype: ElementTree.Element
        @return: subject as ElementTree XML element
        """
        if not isinstance(status, Status):
            raise TypeError("Expecting %r class got %r" % (status, 
                                                           type(Status)))
            
        tag = str(QName.fromGeneric(Status.DEFAULT_ELEMENT_NAME))  
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI)
        
        statusCodeElem = StatusCodeElementTree.toXML(status.statusCode)
        elem.append(statusCodeElem)
        
        # Status message is optional
        if status.statusMessage is not None and \
           status.statusMessage.value is not None:
            statusMessageElem = StatusMessageElementTree.toXML(
                                                        status.statusMessage)
            elem.append(statusMessageElem)
        
        if status.statusDetail is not None:
            raise NotImplementedError("StatusDetail XML serialisation is not "
                                      "implemented")
            
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML Status object
        
        @type elem: ElementTree.Element
        @param elem: subject as ElementTree XML element
        @rtype: saml.saml2.core.Status
        @return: SAML subject
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != Status.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" element found' %
                                      Status.DEFAULT_ELEMENT_LOCAL_NAME)
            
        if len(elem) < 1:
            raise XMLTypeParseError("Expecting a StatusCode child element for "
                                    "SAML Status element")
            
        status = Status()
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == StatusCode.DEFAULT_ELEMENT_LOCAL_NAME:
                status.statusCode = StatusCodeElementTree.fromXML(childElem)
                
            elif localName == StatusMessage.DEFAULT_ELEMENT_LOCAL_NAME:
                status.statusMessage = StatusMessageElementTree.fromXML(
                                                                childElem)
            elif localName == StatusDetail.DEFAULT_ELEMENT_LOCAL_NAME:
                raise NotImplementedError("XML parse of %s element is not "
                                    "implemented" %
                                    StatusDetail.DEFAULT_ELEMENT_LOCAL_NAME)
            else:
                raise XMLTypeParseError("Status child element name %r not "
                                        "recognised" % localName)
       
        return status
    
    
class AttributeQueryElementTree(AttributeQuery):
    """Represent a SAML Attribute Query in XML using ElementTree"""
        
    @classmethod
    def toXML(cls, attributeQuery, **attributeValueElementTreeFactoryKw):
        """Create an XML representation of the input SAML Attribute Query
        object

        @type attributeQuery: saml.saml2.core.AttributeQuery
        @param attributeQuery: SAML Attribute Query
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: ElementTree.Element
        @return: Attribute Query as ElementTree XML element
        """
        if not isinstance(attributeQuery, AttributeQuery):
            raise TypeError("Expecting %r class got %r" % (AttributeQuery, 
                                                        type(attributeQuery)))
            
        
        issueInstant = SAMLDateTime.toString(attributeQuery.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: attributeQuery.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(attributeQuery.version)
        }
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)
        
        issuerElem = IssuerElementTree.toXML(attributeQuery.issuer)
        elem.append(issuerElem)

        subjectElem = SubjectElementTree.toXML(attributeQuery.subject)
        elem.append(subjectElem)

        for attribute in attributeQuery.attributes:
            # Factory enables support for multiple attribute types
            attributeElem = AttributeElementTree.toXML(attribute,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML AttributeQuery object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the AttributeQuery
        @rtype: saml.saml2.core.AttributeQuery
        @return: AttributeQuery object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.VERSION_ATTRIB_NAME,
                              cls.ISSUE_INSTANT_ATTRIB_NAME,
                              cls.ID_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                 'element' %
                                 (attributeName,
                                  cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(attributeValues[0])
        if attributeQuery.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(attributeQuery.version)))
            
        attributeQuery.issueInstant = SAMLDateTime.fromString(
                                                            attributeValues[1])
        attributeQuery.id = attributeValues[2]
        
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                attributeQuery.issuer = IssuerElementTree.fromXML(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Subject
                attributeQuery.subject = SubjectElementTree.fromXML(childElem)
            
            elif localName == Attribute.DEFAULT_ELEMENT_LOCAL_NAME:
                attribute = AttributeElementTree.fromXML(childElem)
                attributeQuery.attributes.append(attribute)
            else:
                raise XMLTypeParseError("Unrecognised AttributeQuery child "
                                          "element \"%s\"" % localName)
        
        return attributeQuery
        
    
class ResponseElementTree(Response):
    """Represent a SAML Response in XML using ElementTree"""
        
    @classmethod
    def toXML(cls, response, **attributeValueElementTreeFactoryKw):
        """Create an XML representation of the input SAML Response
        object

        @type response: saml.saml2.core.Response
        @param response: SAML Response
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        factory
        @rtype: ElementTree.Element
        @return: Response as ElementTree XML element
        """
        if not isinstance(response, Response):
            raise TypeError("Expecting %r class, got %r" % (Response, 
                                                            type(response)))
         
        if response.id is None:
            raise TypeError("SAML Response id is not set")
          
        if response.issueInstant is None:
            raise TypeError("SAML Response issueInstant is not set")
        
        # TODO: Does inResponseTo have to be set?  This implementation 
        # currently enforces this ...
        if response.inResponseTo is None:
            raise TypeError("SAML Response inResponseTo identifier is not set")
        
        issueInstant = SAMLDateTime.toString(response.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: response.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            cls.IN_RESPONSE_TO_ATTRIB_NAME: response.inResponseTo,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(response.version)
        }
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))        
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)

        # Issuer may be omitted: saml-profiles-2.0-os Section 4.1.4.2
        if response.issuer is not None: 
            issuerElem = IssuerElementTree.toXML(response.issuer)
            elem.append(issuerElem)

        statusElem = StatusElementTree.toXML(response.status)       
        elem.append(statusElem)

        for assertion in response.assertions:
            # Factory enables support for multiple attribute types
            assertionElem = AssertionElementTree.toXML(assertion,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(assertionElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem, **attributeValueElementTreeFactoryKw):
        """Parse ElementTree element into a SAML Response object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the Response
        @type attributeValueElementTreeFactoryKw: dict
        @param attributeValueElementTreeFactoryKw: keywords for AttributeValue
        @rtype: saml.saml2.core.Response
        @return: Response object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != Response.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                      Response.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (Response.VERSION_ATTRIB_NAME,
                              Response.ISSUE_INSTANT_ATTRIB_NAME,
                              Response.ID_ATTRIB_NAME,
                              Response.IN_RESPONSE_TO_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                        'element' %
                                        (attributeName,
                                         Response.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        response = Response()
        response.version = SAMLVersion(attributeValues[0])
        if response.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(response.version)))
            
        response.issueInstant = SAMLDateTime.fromString(attributeValues[1])
        response.id = attributeValues[2]
        response.inResponseTo = attributeValues[3]
        
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                response.issuer = IssuerElementTree.fromXML(childElem)
            
            elif localName == Status.DEFAULT_ELEMENT_LOCAL_NAME:
                # Get status of response
                response.status = StatusElementTree.fromXML(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Subject
                response.subject = SubjectElementTree.fromXML(childElem)
            
            elif localName == Assertion.DEFAULT_ELEMENT_LOCAL_NAME:
                assertion = AssertionElementTree.fromXML(childElem,
                                        **attributeValueElementTreeFactoryKw)
                response.assertions.append(assertion)
            else:
                raise XMLTypeParseError('Unrecognised Response child '
                                          'element "%s"' % localName)
        
        return response


class ActionElementTree(Action):
    """Represent a SAML authorization action in XML using ElementTree"""
    
    @classmethod
    def toXML(cls, action):
        """Create an XML representation of the input SAML Name Identifier
        object
        @type action: saml.saml2.core.Action
        @param action: SAML subject
        @rtype: ElementTree.Element
        @return: Name ID as ElementTree XML element
        """
        
        if not isinstance(action, Action):
            raise TypeError("Expecting %r class got %r" % (Action, 
                                                           type(action)))
            
        if not action.namespace:
            raise AttributeError("No action namespace set")
        
        attrib = {
            cls.NAMESPACE_ATTRIB_NAME: action.namespace
        }
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, action.qname.prefix,
                                action.qname.namespaceURI,
                                **attrib)
        elem = ElementTree.Element(tag, **attrib)
        
        if not action.value:
            raise AttributeError("No action name set")
         
        elem.text = action.value

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML Action object
        
        @type elem: ElementTree.Element
        @param elem: Name ID as ElementTree XML element
        @rtype: saml.saml2.core.Action
        @return: SAML Name ID
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        action = Action()
        namespace = elem.attrib.get(cls.NAMESPACE_ATTRIB_NAME)
        if namespace is None:
            log.warning('No "%s" attribute found in "%s" element assuming '
                        '%r action namespace' %
                        (cls.NAMESPACE_ATTRIB_NAME,
                         cls.DEFAULT_ELEMENT_LOCAL_NAME,
                         action.namespace))
        else:
            action.namespace = namespace
            
        action.value = elem.text.strip() 
        
        return action
    
    
class AuthzDecisionQueryElementTree(AuthzDecisionQuery):
    """Represent a SAML Attribute Query in XML using ElementTree"""
        
    @classmethod
    def toXML(cls, authzDecisionQuery):
        """Create an XML representation of the input SAML Authorization
        Decision Query object

        @type authzDecisionQuery: saml.saml2.core.AuthzDecisionQuery
        @param authzDecisionQuery: SAML Authorization Decision Query
        @rtype: ElementTree.Element
        @return: Attribute Query as ElementTree XML element
        """
        if not isinstance(authzDecisionQuery, AuthzDecisionQuery):
            raise TypeError("Expecting %r class got %r" % (AuthzDecisionQuery, 
                                                    type(authzDecisionQuery)))
            
        if not authzDecisionQuery.resource:
            raise AttributeError("No resource has been set for the "
                                 "AuthzDecisionQuery")
            
        issueInstant = SAMLDateTime.toString(authzDecisionQuery.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: authzDecisionQuery.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(authzDecisionQuery.version),
            
            cls.RESOURCE_ATTRIB_NAME: authzDecisionQuery.resource
        }
        
        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                **attrib)
        
        issuerElem = IssuerElementTree.toXML(authzDecisionQuery.issuer)
        elem.append(issuerElem)

        subjectElem = SubjectElementTree.toXML(authzDecisionQuery.subject)
        elem.append(subjectElem)

        for action in authzDecisionQuery.actions:
            # Factory enables support for multiple attribute types
            actionElem = ActionElementTree.toXML(action)
            elem.append(actionElem)
        
        if (authzDecisionQuery.evidence and 
            len(authzDecisionQuery.evidence.evidence) > 0):
            raise NotImplementedError("Conversion of AuthzDecisionQuery "
                                      "Evidence type to ElementTree Element is "
                                      "not currently supported")
            
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML AuthzDecisionQuery object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the AuthzDecisionQuery
        @rtype: saml.saml2.core.AuthzDecisionQuery
        @return: AuthzDecisionQuery object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.VERSION_ATTRIB_NAME,
                              cls.ISSUE_INSTANT_ATTRIB_NAME,
                              cls.ID_ATTRIB_NAME,
                              cls.RESOURCE_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                 'element' %
                                 (attributeName,
                                  cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        authzDecisionQuery = AuthzDecisionQuery()
        authzDecisionQuery.version = SAMLVersion(attributeValues[0])
        if authzDecisionQuery.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(authzDecisionQuery.version)))
            
        authzDecisionQuery.issueInstant = SAMLDateTime.fromString(
                                                            attributeValues[1])
        authzDecisionQuery.id = attributeValues[2]        
        authzDecisionQuery.resource = attributeValues[3]
        
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                authzDecisionQuery.issuer = IssuerElementTree.fromXML(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Subject
                authzDecisionQuery.subject = SubjectElementTree.fromXML(childElem)
            
            elif localName == Action.DEFAULT_ELEMENT_LOCAL_NAME:
                action = ActionElementTree.fromXML(childElem)
                authzDecisionQuery.actions.append(action)
            else:
                raise XMLTypeParseError("Unrecognised AuthzDecisionQuery child "
                                        "element \"%s\"" % localName)
        
        return authzDecisionQuery

def _getElementTreeImplementationForQName(qname):
    key = ("{%s}%s" % (qname.namespaceURI, qname.localPart))
    return _extensionElementTreeMap.get(key)

def setElementTreeImplementationForQName(qname, impl):
    key = ("{%s}%s" % (qname.namespaceURI, qname.localPart))
    _extensionElementTreeMap[key] = impl

