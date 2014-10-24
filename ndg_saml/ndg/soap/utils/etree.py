"""ElementTree Utilities package for NDG SOAP Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/04/09"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: etree.py 7131 2010-06-30 13:37:48Z pjkersha $'
from ndg.saml import Config, importElementTree
ElementTree = importElementTree()

import re


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

class QName(ElementTree.QName):
    """XML Qualified Name for ElementTree
    
    Extends ElementTree implementation for improved attribute access support
    """ 
    # ElementTree tag is of the form {namespace}localPart.  getNs extracts the
    # namespace from within the brackets but if not found returns ''
    getNs = staticmethod(lambda tag: getattr(re.search('(?<=\{).+(?=\})', tag),
                                             'group', 
                                             str)())
                                             
    getLocalPart = staticmethod(lambda tag: tag.rsplit('}', 1)[-1])
    
    def __init__(self, namespaceURI, tag=None, prefix=None):
        """Initialise a qualified name
        
        @param namespaceURI: element namespace URI
        @type namespaceURI: basestring
        @param tag: element local name
        @type tag: basestring
        @param prefix: XML namespace prefix
        @type prefix: basestring
        """
        ElementTree.QName.__init__(self, namespaceURI, tag=tag)
        
        if tag:
            self.namespaceURI = namespaceURI
            self.localPart = tag
        else:
            self.namespaceURI = QName.getNs(namespaceURI)
            self.localPart = QName.getLocalPart(namespaceURI)
            
        self.prefix = prefix

    def __eq__(self, qname):
        """Enable equality check for QName
        @type qname: ndg.security.common.utils.etree.QName
        @param qname: Qualified Name to compare with self 
        @return: True if names are equal
        @rtype: bool
        """
        if not isinstance(qname, QName):
            raise TypeError('Expecting %r; got %r' % (QName, type(qname)))
                            
        return (self.prefix, self.namespaceURI, self.localPart) == \
               (qname.prefix, qname.namespaceURI, qname.localPart)

    def __ne__(self, qname):
        """Enable equality check for QName
        @type qname: ndg.security.common.utils.etree.QName
        @param qname: Qualified Name to compare with self 
        @return: True if names are not equal
        @rtype: bool
        """
        return not self.__eq__(qname)
               
    def _getPrefix(self):
        return self.__prefix

    def _setPrefix(self, value):
        self.__prefix = value
    
    prefix = property(_getPrefix, _setPrefix, None, "Prefix")

    def _getLocalPart(self):
        return self.__localPart
    
    def _setLocalPart(self, value):
        self.__localPart = value
        
    localPart = property(_getLocalPart, _setLocalPart, None, "LocalPart")

    def _getNamespaceURI(self):
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        self.__namespaceURI = value
  
    namespaceURI = property(_getNamespaceURI, _setNamespaceURI, None, 
                            "Namespace URI'")


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
