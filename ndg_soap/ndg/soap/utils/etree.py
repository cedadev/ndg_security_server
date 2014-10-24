"""ElementTree Utilities package for NDG SOAP Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/04/09"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
try: # python 2.5
    from xml.etree import ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import ElementTree

import re


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
    '''Lightweight pretty printing of ElementTree elements'''
    
    # Keep track of namespace declarations made so they're not repeated
    declaredNss = []
    
    _prettyPrint = _PrettyPrint(declaredNss)
    return _prettyPrint(*arg, **kw)


class _PrettyPrint(object):
    def __init__(self, declaredNss):
        self.declaredNss = declaredNss
    
    @staticmethod
    def estrip(elem):
        ''' Just want to get rid of unwanted whitespace '''
        if elem is None:
            return ''
        else:
            # just in case the elem is another simple type - e.g. int - 
            # wrapper it as a string
            return str(elem).strip()
        
    def __call__(self, elem, indent='', html=0, space=' '*4):
        '''Most of the work done in this wrapped function - wrapped so that
        state can be maintained for declared namespace declarations during
        recursive calls using "declaredNss" above'''  
        strAttribs = []
        for attr, attrVal in elem.attrib.items():
            nsDeclaration = ''
            
            attrNamespace = QName.getNs(attr)
            if attrNamespace:
                nsPrefix = ElementTree._namespace_map.get(attrNamespace)
                if nsPrefix is None:
                    raise KeyError('prettyPrint: missing namespace "%s" for ' 
                                   'ElementTree._namespace_map'%attrNamespace)
                
                attr = "%s:%s" % (nsPrefix, QName.getLocalPart(attr))
                
                if attrNamespace not in self.declaredNss:
                    nsDeclaration = ' xmlns:%s="%s"' % (nsPrefix,attrNamespace)
                    self.declaredNss.append(attrNamespace)
                
            strAttribs.append('%s %s="%s"' % (nsDeclaration, attr, attrVal))
            
        strAttrib = ''.join(strAttribs)
        
        namespace = QName.getNs(elem.tag)
        nsPrefix = ElementTree._namespace_map.get(namespace)
        if nsPrefix is None:
            raise KeyError('prettyPrint: missing namespace "%s" for ' 
                           'ElementTree._namespace_map' % namespace)
            
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
                _prettyPrint = _PrettyPrint(declaredNss)
                result += '\n'+ _prettyPrint(child, indent=indent+space) 
                
            result += '\n%s%s</%s>' % (indent,
                                     _PrettyPrint.estrip(child.tail),
                                     tag)
        else:
            result += '</%s>' % tag
            
        return result

