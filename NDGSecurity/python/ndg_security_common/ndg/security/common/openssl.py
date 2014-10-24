"""OpenSSL utilities module - contains OpenSSLConfig class for
parsing OpenSSL configuration files

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "08/02/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import re, os
from ConfigParser import SafeConfigParser
from M2Crypto.X509 import X509_Name

#_____________________________________________________________________________        
class OpenSSLConfigError(Exception):
    """Exceptions related to OpenSSLConfig class"""   


#_____________________________________________________________________________        
class OpenSSLConfig(SafeConfigParser, object):
    """Wrapper to OpenSSL Configuration file to allow extraction of
    required distinguished name used for making certificate requests
    
    @type _certReqDNParamName: tuple
    @cvar _certReqDNParamName: permissable keys for Distinguished Name
    (not including CN which gets set separately).  This is used in __setReqDN
    to check input
    
    @type _caDirPat: string
    @cvar _caDirPat: sub-directory path to CA config directory
    @type __gridCASubDir: string
    @cvar __gridCASubDir: sub-directory of globus user for CA settings"""
    
    _certReqDNParamName = X509_Name.nid.keys()
    
    _caDirPat = re.compile('\$dir')
    
    __gridCASubDir = os.path.join(".globus", "simpleCA")

    
    def __init__(self, filePath=None, caDir=None):
        """Initial OpenSSL configuration optionally setting a file path to
        read from
        
        @type filePath: string        
        @param filePath: path to OpenSSL configuration file
        
        @type caDir: string
        @param caDir: directory for SimpleCA.  This is substituted for $dir
        in OpenSSL config file where present.  caDir can be left out in 
        which case the substitution is not done"""
        
        SafeConfigParser.__init__(self)
        
        self.__reqDN = None
        self.__setFilePath(filePath)

        # Set-up CA directory
        self.setCADir(caDir)

            
    def __setFilePath(self, filePath):
        """Set property method
        @type filePath: string
        @param filePath: path for OpenSSL configuration file"""
        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise OpenSSLConfigError, \
                    "Input OpenSSL config file path must be a string"

            try:
                if not os.access(filePath, os.R_OK):
                    raise OpenSSLConfigError, "not found or no read access"
                                         
            except Exception, e:
                raise OpenSSLConfigError, \
                    "OpenSSL config file path is not valid: \"%s\": %s" % \
                    (filePath, str(e))
                    
        self.__filePath = filePath
                    


    def __getFilePath(self):
        """Get property method
        @rtype: string
        @return: file path for OpenSSL configuration file"""
        return self.__filePath

    filePath = property(fget=__getFilePath,
                        fset=__setFilePath,
                        doc="file path for configuration file")

            
    def setCADir(self, caDir):
        """Set property method
        @type caDir: string
        @param caDir: path for OpenSSL configuration file"""
        if caDir is None:
            # Try to set default from 'HOME' env variable
            homeDir = os.environ.get('HOME')
            if homeDir:
                self.__caDir = os.path.join(os.environ['HOME'], 
                                            self.__gridCASubDir)
            else:
                self.__caDir = None
        else:
            if not isinstance(caDir, basestring):
                raise OpenSSLConfigError, \
                    "Input OpenSSL CA directory path must be a string"

            try:
                if not os.access(caDir, os.R_OK):
                    raise OpenSSLConfigError, "not found or no read access"
                                         
            except Exception, e:
                raise OpenSSLConfigError, \
                    "OpenSSL CA directory path is not valid: \"%s\": %s" % \
                    (caDir, str(e))
                    
        self.__caDir = caDir
                    

    def __getCADir(self):
        """Get property method
        @rtype caDir: string
        @return caDir: directory path for CA configuration files"""
        return self.__caDir

    caDir = property(fget=__getCADir,
                     fset=setCADir,
                     doc="directory path for CA configuration files")


    def __getReqDN(self):
        """Get property method
        @rtype reqDN: dict
        @return reqDN: Distinguished Name for certificate request"""
        return self.__reqDN


    def __setReqDN(self, reqDN):
        """Set property method
        @type reqDN: dict
        @param reqDN: Distinguished Name for certificate request"""
        if not isinstance(reqDN, dict):
            raise AttributeError, "Distinguished Name must be dict type"
        
        invalidKw = [k for k in dict \
                     if k not in self.__class__._certReqDNParamName]
        if invalidKw:
            raise AttributeError, \
    "Invalid certificate request keyword(s): %s.  Valid keywords are: %s" % \
    (', '.join(invalidKw), ', '.join(self.__class__._certReqDNParamName))

        self.__reqDN = reqDN


    reqDN = property(fget=__getReqDN,
                     fset=__setReqDN,
                     doc="Distinguished Name for certificate request")
    
    def read(self):
        """Override base class version to avoid parsing error with the first
        'RANDFILE = ...' part of the openssl file.  Also, reformat _sections 
        to allow for the style of SSL config files where section headings can 
        have spaces either side of the brackets e.g. 
        [ sectionName ] 
        
        and comments can occur on the same line as an option e.g. 
        option = blah # This is option blah
        
        Reformat _sections to """
        try:
            file_ = open(self.__filePath)
            fileTxt = file_.read()
        except Exception, e:
            raise OpenSSLConfigError, \
                "Error reading OpenSSL config file \"%s\": %s" % \
                                                    (self.__filePath, str(e))

        idx = re.search('\[\s*\w*\s*\]', fileTxt).span()[0]
        file_.seek(idx)
        SafeConfigParser.readfp(self, file_)
        
        # Filter section names and reomve comments from options
        for section, val in self._sections.items():
            newSection = section
            self._sections[newSection.strip()] = \
                                    dict([(opt, self._filtOptVal(optVal))
                                          for opt, optVal in val.items()])
            del self._sections[section]
       
        self._set_required_dn_params()

    
    def _filtOptVal(self, optVal):
        """For option value, filter out comments and substitute $dir with
        the CA directory location
        
        @type optVal: string
        @param optVal: option value"""
        filtVal = optVal.split('#')[0].strip()
        if self.__caDir:
            # Replace $dir with CA directory path
            return self.__class__._caDirPat.sub(self.__caDir, filtVal)
        else:
            # Leave $dir in place as no CA directory has been set
            return filtVal
        

    def readfp(self, fp):
        """Set to not implemented as using a file object could be problematic
        given read() has to seek ahead to the first actual section to avoid
        parsing errors"""
        raise NotImplementedError, "Use read method instead"
        self._parseReqDN()


    def _set_required_dn_params(self):
        """Set Required DN parameters from the configuration file returning
        them in a dictionary"""
        
        # Nb. Match over line boundaries
        try:
            self.__reqDN = \
            {
                'O': self.get('req_distinguished_name', 
                              '0.organizationName_default'),
                'OU': self.get('req_distinguished_name', 
                               '0.organizationalUnitName_default')
            }
        except Exception, e:
            raise OpenSSLConfigError, \
            'Error setting content of Distinguished Name from file "%s": %s'%\
                                                    (self.__filePath, str(e))