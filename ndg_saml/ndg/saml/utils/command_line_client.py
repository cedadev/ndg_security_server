'''
Created on Feb 18, 2013

@author: philipkershaw
'''
import sys
from optparse import OptionParser
from uuid import uuid4
from datetime import datetime

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.soap.utils.etree import prettyPrint

from ndg.saml.saml2.binding.soap.client.authzdecisionquery import \
    AuthzDecisionQuerySslSOAPBinding
    
from ndg.saml.saml2.binding.soap.client.attributequery import \
    AttributeQuerySslSOAPBinding
    
from ndg.saml.saml2.core import (SAMLVersion, Subject, NameID, Issuer, 
                                 AuthzDecisionQuery, AttributeQuery,
                                 Attribute, Action, StatusCode,
                                 XSStringAttributeValue)
from ndg.saml.xml.etree import ResponseElementTree


class SamlSoapCommandLineClient(object):
    '''Simple SAML SOAP Client'''
    CONFIG_FILENAME = 'authz-decision-interface.ini'
    
    __slots__ = (
        "service_uri",
        "issuer", 
        "issuer_format",
        "subject_id", 
        "subject_id_format",
        "resource_id", 
        "action", 
        "action_namespace",
        "attribute_names",
        "attribute_friendly_names",
        "attribute_formats",
        "ca_cert_dir",
        "client_cert_filepath",
        "client_prikey_filepath",
        "pretty_print",
        "clock_skew_tolerance",
        "debug"
    )
    
    ATTRIBUTE_QUERY_CMD = 'attr'
    AUTHZ_DECISION_QUERY_CMD = 'authz'
    
    def __init__(self):
        for i in self.__class__.__slots__:
            setattr(self, i, None)
        
    def parse_command_line(self, argv):
        usage = """usage: %prog [command] [options]

commands:
  authz       Make a SAML Authorisation Decision Query
  attr        Make a SAML Attribute Query
"""
        parser = OptionParser(usage=usage)
        
        # List of generic options
        parser.add_option("-u", "--service_uri", dest="service_uri",
                          help="URI for SAML service", 
                          default='',
                          metavar="SERVICE_URI")
        
        parser.add_option("-i", "--issuer", dest="issuer",
                          help="Identity of issuer of this request", 
                          default="/O=Site A/CN=PEP",
                          metavar="ISSUER")
        
        parser.add_option("-I", "--issuer_format", dest="issuer_format",
                          help="Format for request issuer, default is X.509 "
                               "subject name", 
                          default=Issuer.X509_SUBJECT,
                          metavar="ISSUER_FORMAT")
                               
        parser.add_option("-s", "--subject",
                          dest="subject_id", 
                          help="Subject ID about which the request is being "
                               "made - typically a user ID or username",
                          default='',
                          metavar="SUBJECT_ID")
                               
        parser.add_option("-S", "--subject_id_format",
                          dest="subject_id_format", 
                          help="Format for subject ID, defaults to X.509 "
                               "subject name format",
                          default=NameID.X509_SUBJECT,
                          metavar="SUBJECT_ID_FORMAT") 
   
        parser.add_option("-c", "--cert",
                          dest="client_cert_filepath", 
                          help="SSL client certificate for authentication with "
                               "service",
                          metavar="CERT")
   
        parser.add_option("-k", "--key",
                          dest="client_prikey_filepath", 
                          help="SSL client private key for authentication with "
                               "service",
                          metavar="KEY")
   
        parser.add_option("-C", "--ca-cert-dir",
                          dest="ca_cert_dir", 
                          help="Directory containing accepted CA certificates. "
                               "Peer must have an SSL certificate issued from "
                               "one of these.",
                          metavar="CA_CERT_DIR")
   
        parser.add_option("-p", "--pretty-print",
                          dest="pretty_print", 
                          action="store_true",
                          help="Set to true to pretty print SAML responses",
                          metavar="PRETTY_PRINT")
                  
        parser.add_option("-t", "--clock_skew_tolerance",
                          dest="clock_skew_tolerance", 
                          help="Permitted tolerance of +/- n seconds for clock "
                               "skew between client and server when verifying "
                               "time stamps",
                          default=1.,
                          type="float",
                          metavar="CLOCK_SKEW_TOLERANCE")
        
        parser.add_option("-d", "--debug",
                          dest="debug", 
                          action="store_true",
                          help="Set log level to debug for additional error "
                               "output",
                          metavar="DEBUG")
        
        # Allow syntax whereby the first argument is a command - much as openssl
        # does
        n_args = len(argv)
        if n_args < 2:
            parser.error('No command set')
        else:
            command = argv[1]
        
        # Catch example of just specifying --help or '-h'
        if command in ('--help', '-h'):
            parser.print_usage()
            return
          
        elif command == self.__class__.AUTHZ_DECISION_QUERY_CMD:
            # Set options which are specific to authorisation decision queries            
            parser.set_usage('usage: %prog ' + \
                             self.__class__.AUTHZ_DECISION_QUERY_CMD + \
                             ' [options]')
                             
            parser.add_option("-r", "--resource",
                              dest="resource_id", 
                              help="Resource ID to check for access to "
                                   "(for testing authorisation request ONLY)",
                              default='',
                              metavar="RESOURCE_URI")
                                          
            parser.add_option("-a", "--action",
                              dest="action", 
                              help="Requested action - value determined by "
                                   "Action namespace e.g. GET for action "
                                   "namespace %r" % Action.HTTP_GET_ACTION,
                              default=Action.HTTP_GET_ACTION,
                              metavar="ACTION")
                               
            parser.add_option("-A", "--action_namespace",
                              dest="action_namespace", 
                              help="Namespace for requested action",
                              default=Action.GHPP_NS_URI,
                              metavar="ACTION_NS")
                
        elif command == self.__class__.ATTRIBUTE_QUERY_CMD:
            # Set options which are specific to attribute queries            
            parser.set_usage('usage: %prog ' + \
                             self.__class__.ATTRIBUTE_QUERY_CMD + \
                             ' [options]')
            
            parser.add_option("-a", "--attribute_name",
                              dest="attribute_names",
                              action="append", 
                              help="Query for a specific attribute name.  This "
                                   "option can be provided more than once in "
                                   "order to query more than one name.  If "
                                   "this option is not set, a generic query of "
                                   "all available attributes will be made.  "
                                   "This option should be used in conjunction "
                                   "with options the -f/--"
                                   "attribute_friendly_name and "
                                   "-F/--attribute_format.",
                              default=[],
                              metavar="ATTRIBUTE_NAME")
            
            parser.add_option("-f", "--attribute_friendly_name",
                              dest="attribute_friendly_names",
                              action="append", 
                              help="Friendly name is an optional alias to "
                                   "attribute name.  It can be used more than "
                                   "once to specify multiple attributes but "
                                   "if used, make sure it corresponds exactly "
                                   "to the '--attribute_name' settings",
                              default=[],
                              metavar="ATTRIBUTE_FRIENDLY_NAME")            
            
            parser.add_option("-F", "--attribute_format",
                              dest="attribute_formats",
                              action="append", 
                              help="Set the format of the attribute set with "
                                   "the corresponding '--attribute_name'. "
                                   "The option must be set the same number of "
                                   "times as '--attribute_name'.  However, if "
                                   "you wish ALL attributes to use the same "
                                   "format, it is possible to indicate this by "
                                   "setting it just once.",
                              default=[
                                XSStringAttributeValue.TYPE_NAME.namespaceURI],
                              metavar="ATTRIBUTE_FORMAT")
        elif n_args < 3:
            parser.error('No command options set')
            
        else:
            parser.error('Command %s not supported' % command)

        # Leave the command option out of the parser's processing
        options = parser.parse_args(argv[2:])[0]
        
        # Post-processing needed for attribute query
        if command == self.__class__.ATTRIBUTE_QUERY_CMD:
            len_attribute_names = len(options.attribute_names)
            if len_attribute_names > 0:
                len_attribute_friendly_names = len(
                                            options.attribute_friendly_names)
                if (len_attribute_friendly_names > 0 and
                    len_attribute_friendly_names != len_attribute_names):
                    parser.error("The -f/--attribute_friendly_name option must "
                                 "be set so that it corresponds exactly with "
                                 "the number of -a/--attribute_name options "
                                 "set")
                else:
                    options.attribute_friendly_names = [None
                                                        ]*len_attribute_names
                    
                len_attribute_formats = len(options.attribute_formats)
                
                # A single format setting is allowed which will be applied to 
                # all attributes queried for, else set a format individually for
                # each attribute set
                if len_attribute_formats not in (len_attribute_names, 1):
                    parser.error("The -F/--attribute_format option should be "
                                 "set either once to denote all attributes, or "
                                 "once for each attribute set with the "
                                 "-a/--attribute_name option")
                 
                # If a single format was for more than one attribute, then 
                # expand this so that it is a list of the same size - makes 
                # easier for processing
                if len_attribute_names > 1 and len_attribute_formats == 1:
                    options.attribute_formats = options.attribute_formats * \
                                                    len_attribute_names
  
        missing_vals = []
        for i in (self.__class__.__slots__):
            val = getattr(options, i, None)
            if val == '':
                missing_vals.append(i)
            else:
                setattr(self, i, val)
                
        if len(missing_vals) > 0:
            parser.error('Missing option or options: %r' % missing_vals)
            
        return command
    
    def _set_query_common_attrs(self, query):
        """Set attributes common to both types of SAML query"""
        query.version = SAMLVersion(SAMLVersion.VERSION_20)
        query.id = str(uuid4())
        query.issueInstant = datetime.utcnow()
        
        query.issuer = Issuer()
        query.issuer.format = self.issuer_format
        query.issuer.value = self.issuer
        
        query.subject = Subject()
        query.subject.nameID = NameID()
        query.subject.nameID.format = self.subject_id_format
        query.subject.nameID.value = self.subject_id
 
    def create_authz_decision_query(self):
        """Convenience utility to make an Authorisation decision query"""
        authz_decision_query = AuthzDecisionQuery()

        self._set_query_common_attrs(authz_decision_query)
        
        authz_decision_query.resource = self.resource_id
        
        authz_decision_query.actions.append(Action())
        authz_decision_query.actions[-1].namespace = self.action_namespace
        authz_decision_query.actions[-1].value = self.action
            
        return authz_decision_query

    def create_attribute_query(self):
        attr_query = AttributeQuery()

        self._set_query_common_attrs(attr_query)
        
        for i, name in enumerate(self.attribute_names): 
            attribute = Attribute()
            attribute.name = name
            
            if self.attribute_friendly_names[i] is not None:
                attribute.friendlyName = self.attribute_friendly_names[i]
                
            attribute.nameFormat = self.attribute_formats[i]
            
            attr_query.attributes.append(attribute)
        
        return attr_query
                    
    def dispatch(self, command):
        if command == self.__class__.ATTRIBUTE_QUERY_CMD:
            query = self.create_attribute_query()
            binding = AttributeQuerySslSOAPBinding()
            
        elif command == self.__class__.AUTHZ_DECISION_QUERY_CMD:
            query = self.create_authz_decision_query()
            binding = AuthzDecisionQuerySslSOAPBinding()

        binding.sslCACertDir = self.ca_cert_dir
        binding.sslCertFilePath = self.client_cert_filepath
        binding.sslPriKeyFilePath = self.client_prikey_filepath
        binding.clockSkewTolerance = self.clock_skew_tolerance

        response = binding.send(query, uri=self.service_uri)
        
        return response
    
    @classmethod
    def response_successful(cls, response):
        return response.status.statusCode.value == StatusCode.SUCCESS_URI
    
    def display_result(self, response):
        # Convert back to ElementTree instance read for string output
        saml_response_elem = ResponseElementTree.toXML(response)
        
        if self.pretty_print:
            print(prettyPrint(saml_response_elem))
        else:
            print(ElementTree.tostring(saml_response_elem))

    @classmethod
    def main(cls, argv=sys.argv):
        client = cls()
        command = client.parse_command_line(sys.argv)
        if command is None: # top-level help set
            sys.exit(0)
            
        import logging
        if client.debug:
            log_level = logging.NOTSET
        else:
            log_level = logging.CRITICAL
            
        logging.basicConfig(level=log_level)
        
        try:
            response = client.dispatch(command)
        except Exception, e:
            if client.debug:
                raise
            else:
                raise SystemExit(e)
                
        client.display_result(response)
        
        sys.exit(cls.response_successful(response))
    
        
if __name__ == "__main__":
    SamlSoapCommandLineClient.main()
    
        