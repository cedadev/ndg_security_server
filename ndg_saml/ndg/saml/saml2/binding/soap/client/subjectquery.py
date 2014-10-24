"""SAML 2.0 bindings module implements SOAP binding for subject query

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from ndg.saml.saml2.core import SubjectQuery, Subject, NameID
from ndg.saml.saml2.binding.soap.client import SOAPBindingInvalidResponse
from ndg.saml.saml2.binding.soap.client.requestbase import (
    RequestBaseSOAPBinding,)

class SubjectQueryResponseError(SOAPBindingInvalidResponse):
    """SAML Response error from Subject Query"""
    

class SubjectQuerySOAPBinding(RequestBaseSOAPBinding):
    """SAML Subject Query SOAP Binding
    """
    SUBJECT_ID_OPTNAME = 'subjectID'
    SUBJECT_ID_FORMAT_OPTNAME = 'subjectIdFormat'
    
    CONFIG_FILE_OPTNAMES = (
        SUBJECT_ID_OPTNAME,
        SUBJECT_ID_FORMAT_OPTNAME
    )
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in CONFIG_FILE_OPTNAMES])
    del i
    
    QUERY_TYPE = SubjectQuery
    
    def __init__(self, **kw):
        '''Create SOAP Client for a SAML Subject Query'''       
        self.__subjectIdFormat = None
        super(SubjectQuerySOAPBinding, self).__init__(**kw)

    def addQueryAttributes(self, query):
        """Adds to a query attributes that are configured for
        SubjectQuerySOAPBinding.
        """
        super(SubjectQuerySOAPBinding, self).addQueryAttributes(query)
        # Initialise a Subject with the configured format.
        query.subject = Subject()
        nameID = NameID()
        nameID.format = self.subjectIdFormat
        query.subject.nameID = nameID

    def _getSubjectIdFormat(self):
        return self.__subjectIdFormat

    def _setSubjectIdFormat(self, value):
        self.__subjectIdFormat = value

    subjectIdFormat = property(_getSubjectIdFormat, _setSubjectIdFormat, 
                               doc="Subject Name ID format")

    def setQuerySubjectId(self, query, subjectID):
        """Sets the subject ID for a query created by SubjectQuerySOAPBinding or
        a derived class.
        """
        if not query.subject:
            query.subject = Subject()
            nameID = NameID()
            nameID.format = self.subjectIdFormat
        query.subject.nameID.value = subjectID
