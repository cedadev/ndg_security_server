"""Handles configuration of ElementTree libraries.

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "13/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"

class Config(object):
    """Configuration options
    @type use_lxml: bool
    @cvar use_lxml: Controls whether lxml.etree should be imported instead of
    etree. lxml is required for XPath expressions with conditions.
    """
    use_lxml = None

def importElementTree():
    """Imports ElementTree or the lxml ElementTree API depending on the
    Config.use_lxml value and whether the lxml package is found.
    @rtype: module
    @return: the element tree module that has been imported
    """
    if Config.use_lxml is not None:
        if Config.use_lxml:
            from lxml import etree as ElementTree
        else:
            try: # python 2.5
                from xml.etree import ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import ElementTree
    else:
        Config.use_lxml = False
        try:
            from lxml import etree as ElementTree
            Config.use_lxml = True
        except ImportError:
            try: # python 2.5
                from xml.etree import ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import ElementTree
    return ElementTree
