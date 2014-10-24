"""
Generic parsers to use when reading in configuration data
- methods available to deal with both XML and INI (flat text key/val) formats
"""
__author__ = "C Byrom - Tessella"
__date__ = "20/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from ConfigParser import SafeConfigParser, InterpolationMissingOptionError, \
    NoOptionError

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

import logging, os
log = logging.getLogger(__name__)

# lambda function to expand out any environment variables in properties read in
expandEnvVars = lambda x: isinstance(x, basestring) and \
                    os.path.expandvars(x).strip() or x


class CaseSensitiveConfigParser(SafeConfigParser):
    '''
    Subclass the SafeConfigParser - to preserve the original string case of the
    cfg section names - NB, the RawConfigParser default is to lowercase these 
    by default
    '''
    
    def optionxform(self, optionstr):
        return optionstr
        
class ConfigFileParseError(Exception):
    """Raise for errors in configuration file formatting"""

def readAndValidateProperties(propFilePath, validKeys={}, **iniPropertyFileKw):
    """
    Determine the type of properties file and load the contents appropriately.
    If a dict of valid keys is also specified, check the loaded properties 
    against these.
    
    @param propFilePath: file path to properties file - either in xml or ini 
    format
    @type propFilePath: string
    @keywords validKeys: a dictionary of valid values to be read from the file
    - if values are encountered that are not in this list, an exception will be
    thrown
    - if all info should be read, this keyword should be left to its default 
    value
    - NB, this dict will also ensure list data is read in correctly
    @type validKeys: dict
    @raise ValueError: if a key is read in from the file that is not included 
    in the specified validKeys dict
    """
    log.debug("Reading properties from %s" % propFilePath)
    properties = {}
    if propFilePath.lower().endswith('.xml'):
        log.debug("File has 'xml' suffix - treating as standard XML formatted "
                  "properties file")
        log.warning("Current version of code for properties handling with "
                    "XML is untested - may be deprecated")
        properties = readXMLPropertyFile(propFilePath, validKeys)
        # if validKeys set, check that all loaded property values are featured 
        # in this list
        if validKeys:
            validateProperties(properties, validKeys)
        
            # lastly set any default values from the validKeys dict for vals 
            # not read in from the property file
            _setDefaultValues(properties, validKeys)
    else:
        properties = readINIPropertyFile(propFilePath, validKeys,
                                         **iniPropertyFileKw)
        
        # Ugly hack to allow for sections and option prefixes in the validation
        # and setting of defaults
        if validKeys:
            sections = iniPropertyFileKw.get('sections')
            prefix = iniPropertyFileKw.get('prefix')
            if sections is not None:
                for section in sections:
                    if section == 'DEFAULT':
                        propBranch = properties
                    else:
                        propBranch = properties[section]
                        
                    validateProperties(propBranch, validKeys)
                    _setDefaultValues(propBranch, validKeys)
                    
            else:
                validateProperties(properties, validKeys)
                _setDefaultValues(properties, validKeys)

    
    # lastly, expand out any environment variables set in the properties file
    properties = _expandEnvironmentVariables(properties)
    log.info('Properties loaded')
    return properties


def readProperties(propFilePath, validKeys={}, **iniPropertyFileKw):
    """
    Determine the type of properties file and load the contents appropriately.
    @param propFilePath: file path to properties file - either in xml or ini 
    format
    @type propFilePath: string
    """
    log.debug("Reading properties from %s" %propFilePath)
    properties = {}
    if propFilePath.lower().endswith('.xml'):
        log.debug("File has 'xml' suffix - treating as standard XML formatted "
                  "properties file")
        log.warning("Current version of code for properties handling with "
                    "XML is untested - may be deprecated")
        properties = readXMLPropertyFile(propFilePath, validKeys)
    else:
        properties = readINIPropertyFile(propFilePath, validKeys,
                                         **iniPropertyFileKw)
    
    # lastly, expand out any environment variables set in the properties file
    properties = _expandEnvironmentVariables(properties)
    log.info('Properties loaded')
    return properties
        

class INIPropertyFile(object):
    '''INI Property file reading class
    
    __call__ method enables a standalone read function'''
    
    defaultOptionNames = ('here',)
    
    def read(self, 
             propFilePath, 
             validKeys, 
             cfg=None, 
             sections=None,
             defaultItems={}, 
             prefix=''):
        """
        Read 'ini' type property file - i.e. a flat text file with key/value
        data separated into sections
    
        @param propFilePath: file path to properties file - either in xml or 
        ini format
        @type propFilePath: string
        @param validKeys: a dictionary of valid values to be read from the file
        - if values are encountered that are not in this list, an exception 
        will be thrown
        - if all info should be read, set this param to 'None'
        @type validKeys: dict
        @type sections: basestring
        @param sections: sections to be read from - defaults to all sections in the
        file
        @type defaultItems: dict
        @param defaultItems: add items via this input dictionary as well as by
        retrieval from config file itself.  This only comes into effect if
        cfg was not set and a new config object is created locally.
        @rtype: dict
        @return: dict with the loaded properties in
        @raise ValueError: if a key is read in from the file that is not 
        included in the specified validKeys dict
        """
        log.debug("File is not marked as XML - treating as flat 'ini' format "
                  "file")
        
        # Keep a record of property file path setting
        self.propFilePath = propFilePath
            
        if cfg is None:
            # Add default item for file location to enable convenient 
            # substitutions within the file
            defaultItems['here'] = os.path.dirname(propFilePath)
            
            self.cfg = CaseSensitiveConfigParser(defaults=defaultItems)
            self.cfg.read(propFilePath)
            if not os.path.isfile(propFilePath):
                raise IOError('Error parsing properties file "%s": No such '
                              'file' % propFilePath)
        else:
            self.cfg = cfg
               
        properties = {}
        
        if sections is None:
            # NB, add 'DEFAULT' section since this isn't returned by the 
            # 'sections()'
            sections = self.cfg.sections()
            sections.append('DEFAULT')
        
        # parse data from the specified sections of the config file
        for section in sections:
            if section == 'DEFAULT':
                properties.update(_parseConfig(self.cfg, 
                                               validKeys, 
                                               section=section,
                                               prefix=prefix))
            else:                    
                properties[section] = _parseConfig(self.cfg, 
                                                   validKeys, 
                                                   section=section,
                                                   prefix=prefix)
    
                
        # Get rid of 'here' default item to avoid interfering with later
        # processing
        for opt in INIPropertyFile.defaultOptionNames:
            properties.pop(opt, None)
        
        log.debug("Finished reading from INI properties file")
        return properties
    
    # Enables use of this class like a function see below ...
    __call__ = read
    
    
# Enable read INI of file as a one shot call
readINIPropertyFile = INIPropertyFile()   


class INIPropertyFileWithValidation(INIPropertyFile):
    '''Extension of INI Property file reading class to make a callable that
    validates as well as reads in the properties.  Also see 
    readAndValidateINIPropertyFile in this module'''
    
    def readAndValidate(self, propFilePath, validKeys, **kw):
        prop = super(INIPropertyFileWithValidation,self).__call__(propFilePath,
                                                                  validKeys, 
                                                                  **kw)
        
        # Pass wsseSection but respect validateProperties default value
        wsseSection = kw.get('wssSection')
        if wsseSection is not None:
            validatePropKw = {'wsseSection': wsseSection}
        else:
            validatePropKw = {}
            
        validateProperties(prop, validKeys, **validatePropKw)
        return prop
    
    __call__ = readAndValidate
    
# Enable read and validation of INI file as a one shot call
readAndValidateINIPropertyFile = INIPropertyFileWithValidation()


def _parseConfig(cfg, validKeys, section='DEFAULT', prefix=''):
    '''
    Extract parameters from cfg config object
    @param cfg: config object
    @type cfg: CaseSensitiveConfigParser
    @param validKeys: a dictionary of valid values to be read from the file - 
    used to check the type of the input parameter to ensure (lists) are handled 
    correctly
    @type validKeys: dict
    @keyword section: section of config file to parse from
    @type section: string
    @return: dict with the loaded properties in
    '''
    log.debug("Parsing section: %s" % section)

    propRoot = {}
    propThisBranch = propRoot
    
    if section == 'DEFAULT':
        keys = cfg.defaults().keys()
    else:
        keys = cfg.options(section)
        # NB, we need to be careful here - since this will return the section
        # keywords AND the 'DEFAULT' section entries - so use the difference 
        # between the two
        keys = filter(lambda x:x not in cfg.defaults().keys(), keys)

    for key in keys:
        try:
            val = cfg.get(section, key)
        except InterpolationMissingOptionError, e:
            log.warning('Ignoring property "%s": %s' % (key, e))
            continue
        
        # Allow for prefixes - 1st a prefix global to all parameters
#        keyLevels = key.split('.')
#        if prefix:
#            if keyLevels[0] == prefix:
#                keyLevels = keyLevels[1:]
#                if keyLevels == []:
#                    raise ConfigFileParseError('Expecting "%s.<option>"; got '
#                                               '"%s"' % ((prefix,)*2))
#            else:
#                continue           
        if prefix:
            if key.startswith(prefix):
                keyLevels = key.replace(prefix+'.', '', 1).split('.')  
                if keyLevels == []:
                    raise ConfigFileParseError('Expecting "%s.<option>"; got '
                                               '"%s"' % ((prefix,)*2))
            else:
                continue
        else:
            keyLevels = key.split('.')
                        
        # 2nd - prefixes to denote sections
        if len(keyLevels) > 1:
                
            # Nb. This allows only one level of nesting - subsequent levels if
            # present are represented by a concatenation of the levels joined
            # by underscores
            subSectionKey = keyLevels[0]
            subKey = '_'.join(keyLevels[1:])
            if subSectionKey in validKeys and \
               isinstance(validKeys[subSectionKey], dict):
                val = _parseVal(cfg, section, key, validKeys[subSectionKey],
                                subKey=subKey)
                if subSectionKey in propThisBranch:
                    propThisBranch[subSectionKey][subKey] = val
                else:
                    propThisBranch[subSectionKey] = {subKey: val}
        else: 
            # No sub-section present           
            subKey = keyLevels[0]
            val = _parseVal(cfg, section, key, validKeys, subKey=subKey)
            
            # check if key already exists; if so, append to list
            if propThisBranch.has_key(subKey):
                propThisBranch[subKey] = __listify(
                                            propThisBranch[subKey]).extend(val)
            else:
                propThisBranch[subKey] = val

    log.debug("Finished parsing section")
    return propRoot

def _parseVal(cfg, section, option, validKeys, subKey=None):
    '''Convert option to correct type trying each parser config routine in 
    turn.  Convert to a list if validKeys dict item indicates so
    
    @type cfg: ndg.security.common.utils.configfileparsers.CaseSensitiveConfigParser
    @param cfg: config file object
    @type section: basestring
    @param section: section in config file to read from
    @type key: basestring
    @param key: section option to read
    @type validKeys: dict
    @param validKeys: key look-up - if item is set to list type then the option
    value in the config file will be split into a list.'''
    
    if subKey:
        key = subKey
    else:
        key = option
         
    conversionFuncs = (cfg.getint, cfg.getfloat, cfg.getboolean, cfg.get)
    for conversionFunc in conversionFuncs:
        try:
            val = conversionFunc(section, option)
            if val == '':
                # NB, the XML parser will return empty vals as None, so ensure 
                # consistency here
                val = None
                
            elif isinstance(val, basestring):
                # expand out any env vars
                val = expandEnvVars(val)
                
                # ensure it is read in as the correct type
                if key in validKeys and isinstance(validKeys[key], list):
                    # Treat as a list of space separated string type elements
                    # Nb. lists only cater for string type elements
                    val = val.split()
             
            return val
        except ValueError:
            continue
        except Exception, e:
            log.error('Error parsing option "%s" in section "%s": %s' %
                      (section, key, e))
            raise

    raise ValueError('Error parsing option "%s" in section "%s"'%(section,key))

         
def readXMLPropertyFile(propFilePath, validKeys, rootElem=None):
    """
    Read property file - assuming the standard XML schema

    @param propFilePath: file path to properties file - either in xml or ini 
    format
    @type propFilePath: string
    @param validKeys: a dictionary of valid values to be read from the file - 
    used to check the type of the input parameter to ensure (lists) are handled
    correctly
    @keyword rootElem: a particular element of an ElementTree can be passed in 
    to use as the root element; NB, if this is set, it will take precedence 
    over any propFilePath specified
    @type rootElem: ElementTree.Element
    @return: dict with the loaded properties in
    """
    if rootElem is None:
        try:
            tree = ElementTree.parse(propFilePath)
            
        except IOError, ioErr:
            raise ValueError("Error parsing properties file \"%s\": %s" % 
                             (ioErr.filename, ioErr.strerror))
    
        rootElem = tree.getroot()
        if rootElem is None:
            raise ValueError('Parsing properties file "%s": root element is '
                             'not defined' % propFilePath)

    properties = {}
    # Copy properties from file into a dictionary
    try:
        for elem in rootElem:
            key = elem.tag
            val = elem.text

            # expand out any env vars
            val = expandEnvVars(val)

            # if the tag contains an integer, convert this appropriately
            if val and val.isdigit():
                val = int(val)
            
            # check for lists - don't recurse into these else the key names
            # will end up being wrong
            if key in validKeys and isinstance(validKeys[key], list):
                # handle lists of elements
                if len(elem) == 0:
                    if elem.text is not None:
                        # Treat as a list of space separated elements
                        val = val.split()
                else:
                    # Parse from a list of sub-elements
                    val = [expandEnvVars(subElem.text.strip()) \
                           for subElem in elem]
            
            # otherwise check for subelements; if these exist, recurse and 
            # store properties in an inner dictionary
            elif len(elem) > 0:
                val = readXMLPropertyFile(propFilePath,validKeys,rootElem=elem)

            # check if key already exists; if so, append to list
            if properties.has_key(key):
                properties[key] = __listify(properties[key]).extend(val)
            else:
                properties[key] = val
            
    except Exception, e:
        raise ValueError('Error parsing tag "%s" in properties file "%s": %s' %
                         (elem.tag, propFilePath, e))

    log.debug("Finished reading from XML properties file")
    return properties


def __listify(val):
    '''
    Checks if val is a list; if so return as is, if not return as list
    
    @type val: list
    @param val: object to turn into a list
    @rtype: list
    @return: val as a list (if it is not already)
    '''
    if isinstance(val, list):
        return val
    return [val]


def validateProperties(properties, validKeys):
    '''
    Check the contents of the properties dict to ensure it doesn't contain
    any keys not featured in the validKeys dict; if it does, throw an exception
    @param properties: dictionary storing loaded properties
    @type properties: dict
    @param validKeys: a dictionary of valid values
    @type validKeys: dict
    @raise ValueError: if a key is read in from the file that is not included 
    in the specified validKeys dict
    '''
    log.debug("Checking for invalid properties")
    invalidKeys = []
    for key in validKeys:
        # NB, this is a standard property used across most services - so check
        # using the properties listed here
        if validKeys[key] and isinstance(validKeys[key], dict):
            validateProperties(properties.get(key, {}), validKeys[key])
                
        elif key not in properties and nonDefaultProperty(validKeys[key]):
            invalidKeys += [key]

    if invalidKeys != []:
        errorMessage = "The following properties file " + \
            "elements are missing and must be set: " + ', '.join(invalidKeys)
        log.error(errorMessage)
        raise ValueError(errorMessage)

nonDefaultProperty = lambda prop:prop==NotImplemented or prop==[NotImplemented]

def _expandEnvironmentVariables(properties):
    '''
    Iterate through the values in a dict and expand out environment variables
    specified in any non password option entries
    @param properties: dict of properties to expand
    @type properties: dict
    @return: dict with expanded values
    '''
    log.debug("Expanding out environment variables in properties dictionary")
    for key, val in properties.items():
        # only check strings or lists of strings
        if isinstance(val, list):            
            properties[key] = [_expandEnvironmentVariable(key, item) \
                               for item in val]
            
        elif isinstance(val, str):
            properties[key] = _expandEnvironmentVariable(key, val)
            
    log.debug("Finished expanding environment variables")
    return properties


def _expandEnvironmentVariable(key, val):
    '''
    Expand out a val, if it contains environment variables and
    is not password related
    @param key: key name for the value
    @type key: str
    @param val: value to expand env vars out in
    @type val: str
    @rtype: basestring
    @return: val - with any environment variables expanded out
    '''
    if key.lower().find('pwd') == -1 and key.lower().find('password') == -1:
        val = os.path.expandvars(val)
    return val

    
def _setDefaultValues(properties, validKeys, sectionKey=''):
    '''
    Check the contents of the properties dict to ensure it contains all the
    keys featured in the validKeys dict; if any of these are missing or have 
    no value set for them, set up default values for these in the properties 
    dict
    @param properties: dictionary storing loaded properties
    @type properties: dict
    @param validKeys: a dictionary of valid values
    @type validKeys: dict
    @rtype: dict
    @return properties: updated dict with default values for any missing values
    '''
    
    
    if sectionKey:
        sectionKeyDot = sectionKey+'.'
        log.debug("Checking for any unset keys for %s sub-section"%sectionKey)
    else:
        sectionKeyDot = ''
        log.debug("Checking for any unset keys")
        
    for key in validKeys:
        if key not in properties or not properties[key]:
            if validKeys[key] == NotImplemented:
                errorMessage = 'Missing property "%s" must be set.' % key
                log.error(errorMessage)
                raise ValueError(errorMessage)
            
            log.warning("Found missing/unset property - setting default "
                        "values: %s%s=%s" % (sectionKeyDot,key,validKeys[key]))
            properties[key] = validKeys[key]
            
        elif isinstance(properties[key], dict):
            _setDefaultValues(properties[key], validKeys[key], sectionKey=key)
        
    log.debug("Finished checking for unset keys")

