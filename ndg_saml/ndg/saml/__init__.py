"""Implementation of SAML 2.0 for NDG Security

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
__date__ = "22/07/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

class Config(object):
    """Configuration options
    @type use_lxml: bool
    @cvar use_lxml: Controls whether lxml.etree should be imported instead of
    etree. lxml is required for XPath expressions with conditions.
    """
    use_lxml = None

def importElementTreeAndCElementTree():
    """Imports ElementTree and cElementTree, or the lxml ElementTree API,
    depending on the Config.use_lxml value and whether the lxml package is
    found.
    @rtype: tuple (module, module)
    @return: the ElementTree and cElementTree modules that have been imported -
    None is returned instead of cElementTree if lxml is used.
    """
    cElementTree = None
    if Config.use_lxml is not None:
        if Config.use_lxml:
            from lxml import etree as ElementTree
        else:
            try: # python 2.5
                # Force absolute import to prevent clash with
                # ndg.saml.xml.etree.
                p = __import__('xml.etree', globals(), locals(),
                               ['cElementTree', 'ElementTree'], 0)
                cElementTree = p.cElementTree
                ElementTree = p.ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import cElementTree, ElementTree
    else:
        Config.use_lxml = False
        try:
            from lxml import etree as ElementTree
            Config.use_lxml = True
        except ImportError:
            try: # python 2.5
                p = __import__('xml.etree', globals(), locals(),
                               ['cElementTree', 'ElementTree'], 0)
                cElementTree = p.cElementTree
                ElementTree = p.ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import cElementTree, ElementTree
    return (ElementTree, cElementTree)

def importElementTree():
    """Imports ElementTree or the lxml ElementTree API depending on the
    Config.use_lxml value and whether the lxml package is found.
    @rtype: module
    @return: the element tree module that has been imported
    """
    return importElementTreeAndCElementTree()[0]
