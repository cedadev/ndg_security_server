#
# Makefile to copy ndg.security.test.integration configurations and make them
# into templates.  This is intended for use preparing a distribution, not
# for post-installation use.
#
# @author P J Kershaw 16/11/10
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - LICENSE file
#
# $Id$

# Settings for all Templates
ROOT_FILEPATH = ../../../../../
DEST_DIR = ./
TEST_DIR = ${ROOT_FILEPATH}ndg_security_test/ndg/security/test/
TEST_CONFIG_SRC_DIR = ${TEST_DIR}config/
PKI_SRC_DIR = ${TEST_CONFIG_SRC_DIR}pki/
CA_SRC_DIR = ${PKI_SRC_DIR}ca/
SERVER_CERT_SRC_FILEPATH = ${PKI_SRC_DIR}localhost.crt
SERVER_KEY_SRC_FILEPATH = ${PKI_SRC_DIR}localhost.key
INTEGRATION_TEST_DIR = ${TEST_DIR}integration/

USERDB_FILENAME = user.db
USERDB_FILEPATH = ${TEST_CONFIG_SRC_DIR}${USERDB_FILENAME}

# OpenID Provider Specific Settings
OP_SERVER_YADIS_TMPL_SRC_FILENAME = serveryadis.xml
OP_YADIS_TMPL_SRC_FILENAME = yadis.xml


# Generic Services Template Settings
SERVICE_SRC_DIRNAME = full_system/
SERVICE_DEST_DIRNAME = services/
SERVICE_SRC_DIR = ${INTEGRATION_TEST_DIR}${SERVICE_SRC_DIRNAME}
SERVICE_DEST_DIR = ${DEST_DIR}${SERVICE_DEST_DIRNAME}
SERVICE_SRC_INI_FILENAME = securityservices.ini
SERVICE_SRC_INI_FILEPATH = ${SERVICE_SRC_DIR}${SERVICE_SRC_INI_FILENAME}
SERVICE_INI_TMPL_FILEPATH = ${SERVICE_DEST_DIR}service.ini_tmpl
SERVICE_PKI_DEST_DIR = ${SERVICE_DEST_DIR}pki/
SERVICE_CA_DEST_DIR = ${SERVICE_PKI_DEST_DIR}ca/
SERVICE_LOG_DEST_DIR = ${SERVICE_DEST_DIR}log/
SERVICE_LOG_FILEPATH = ${SERVICE_LOG_DEST_DIR}service.log
SERVICE_SURPLUS_FILES = README __init__.* attributeinterface.* securedapp.* \
	request-filter.xml pep_result_handler *.pyc authn/* \
	openidprovider/associations/  openidprovider/beaker/ \
	openidprovider/README openidprovider/nonces/ openidprovider/temp/ \
	openidrelyparty/store/ openidrelyparty/__init__.* \
	pip-session-cache/* log ${SERVICE_SRC_INI_FILENAME}
SERVICE_OP_DIRNAME = openidprovider/
SERVICE_OP_DIR = ${SERVICE_DEST_DIR}${SERVICE_OP_DIRNAME}
SERVICE_OP_TMPL_DIR = ${SERVICE_OP_DIR}templates/
SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH_TMP = ${SERVICE_OP_TMPL_DIR}serveryadis.xml
SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH = ${SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH_TMP}_tmpl
SERVICE_OP_YADIS_TMPL_FILEPATH_TMP = ${SERVICE_OP_TMPL_DIR}yadis.xml
SERVICE_OP_YADIS_TMPL_FILEPATH = ${SERVICE_OP_YADIS_TMPL_FILEPATH_TMP}_tmpl


all: service_tmpl securedapp_tmpl authorisation_service_tmpl \
		attribute_service_tmpl openidprovider_tmpl
			
force: clean all

		
service_tmpl: ${SERVICE_SRC_DIR}
	@-echo Preparing Generic Services template ...
	@-echo ________________________________________________________________________________
	@-echo
	@-echo Copying configuration files ...
	@-cp -r ${SERVICE_SRC_DIR} ${SERVICE_DEST_DIR} 2> /dev/null
	@-echo Clear out SVN directories ...
	@-find ${SERVICE_DEST_DIR} -name ".svn" -print | xargs /bin/rm -rf
	@-echo Remove unneeded files ...
	for i in ${SERVICE_SURPLUS_FILES} ; do \
		rm -rf ${SERVICE_DEST_DIR}$$i ; \
	done ;
	# Make an empty log file so that log directory is included in egg
	@-echo Make log directory ...
	mkdir ${SERVICE_DEST_DIR}log
	touch ${SERVICE_LOG_FILEPATH}
	@-echo Making substitutions for ini file template variables ...
	sed -e s/'portNum = .*'/'portNum = %%\{portNumber}'/ \
	-e s/'baseURI =.*'/'baseURI = %%\{baseURI}'/ \
	-e s/'saml\.soapbinding\.mountPath.*'/'saml.soapbinding.mountPath = %%\{attributeServiceMountPath\}'/ \
	-e s/'saml\.mountPath.*'/'saml.mountPath = %%\{authorisationServiceMountPath\}'/ \
	-e s/'saml\.soapbinding\.issuerName =.*'/'saml.soapbinding.issuerName = %%\{attributeServiceIssuerName}'/ \
	-e s/'saml\.issuerName =.*'/'saml\.issuerName = %%\{authorisationServiceIssuerName}'/ \
	-e s/'saml\.soapbinding\.issuerFormat =.*'/'saml.soapbinding.issuerFormat = %%\{attributeServiceIssuerFormat}'/ \
	-e s/'saml\.issuerFormat =.*'/'saml.issuerFormat = %%\{authorisationServiceIssuerFormat}'/ \
	-e s/'authkitCookieSecret =.*'/'authkitCookieSecret = %%\{authkitCookieSecret}'/ \
	-e s/'beakerSessionCookieSecret =.*'/'beakerSessionCookieSecret = %%\{beakerSessionCookieSecret}'/ \
	-e s/'authkit.openid.session.secret = .*'/'authkit.openid.session.secret = %%\{openidRelyingPartyCookieSecret}'/ \
	-e s/'testConfigDir = .*'// \
	-e s/testConfigDir/here/g \
	-e s/\(os\.path\.join\(\'%\(here\)s\'/\(os.path.join\(\'%%\{outputDir}\'/ \
	-e s/'# Revision:.*'//g \
		${SERVICE_SRC_INI_FILEPATH} > ${SERVICE_INI_TMPL_FILEPATH}
	@-echo Making substitutions for OpenID Provider Yadis templates ...
	sed -r -e /'<Service priority=\"(1|19|30|20)\">'/,/'<\/Service>'/d \
	-e s/'<\/XRD>'/'    %%\{serveryadisExtraServiceEndpoints}\n    <\/XRD>'/ \
		${SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH_TMP} > \
		${SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH}
	rm -f ${SERVICE_OP_SERVER_YADIS_TMPL_FILEPATH_TMP}
	sed -r -e /'<Service priority=\"(1|19|30|20)\">'/,/'<\/Service>'/d \
	-e s/'<\/XRD>'/'    %%\{yadisExtraServiceEndpoints}\n    <\/XRD>'/ \
		${SERVICE_OP_YADIS_TMPL_FILEPATH_TMP} > ${SERVICE_OP_YADIS_TMPL_FILEPATH}
	rm -f ${SERVICE_OP_YADIS_TMPL_FILEPATH_TMP}
	@-echo
	@-echo Create PKI directory and copying files ...
	-mkdir ${SERVICE_PKI_DEST_DIR}
	cp ${SERVER_CERT_SRC_FILEPATH} ${SERVICE_PKI_DEST_DIR}
	cp ${SERVER_KEY_SRC_FILEPATH} ${SERVICE_PKI_DEST_DIR}
	-mkdir ${SERVICE_CA_DEST_DIR}
	cp ${CA_SRC_DIR}* ${SERVICE_CA_DEST_DIR}
	@-echo Copying test SQLite user database ...
	cp ${USERDB_FILEPATH} ${SERVICE_DEST_DIR}
	@-echo
	@-echo Done.
	
service_tmpl_clean:
	@-echo Clearing Services template ...
	rm -rf ${SERVICE_DEST_DIR}


# Secured Application Template Settings
SECUREDAPP_SRC_DIRNAME = full_system/
SECUREDAPP_DEST_DIRNAME = securedapp/
SECUREDAPP_SRC_DIR = ${INTEGRATION_TEST_DIR}${SECUREDAPP_SRC_DIRNAME}
SECUREDAPP_DEST_DIR = ${DEST_DIR}${SECUREDAPP_DEST_DIRNAME}
SECUREDAPP_SRC_INI_FILENAME = securedapp.ini
SECUREDAPP_SRC_INI_FILEPATH = ${SECUREDAPP_SRC_DIR}${SECUREDAPP_SRC_INI_FILENAME}
SECUREDAPP_INI_FILEPATH_TMP = ${SECUREDAPP_DEST_DIR}${SECUREDAPP_SRC_INI_FILENAME}
SECUREDAPP_INI_TMPL_FILEPATH = ${SECUREDAPP_DEST_DIR}service.ini_tmpl
SECUREDAPP_PKI_DEST_DIR = ${SECUREDAPP_DEST_DIR}pki/
SECUREDAPP_CA_DEST_DIR = ${SECUREDAPP_PKI_DEST_DIR}ca/
SECUREDAPP_LOG_DEST_DIR = ${SECUREDAPP_DEST_DIR}log/
SECUREDAPP_LOG_FILEPATH = ${SECUREDAPP_LOG_DEST_DIR}service.log
SECUREDAPP_SURPLUS_FILES = README __init__.* attributeinterface.* \
	securityservices*.* *.pyc authn/* openidprovider/ openidrelyparty/store/ \
	openidrelyparty/__init__.* pip-session-cache/ log/ policy.xml \
	pip-mapping.txt request-filter.xml
SECUREDAPP_REQUEST_FILTER_FILENAME = request-filter.xml
SECUREDAPP_REQUEST_FILTER_TMPL_FILENAME = ${SECUREDAPP_REQUEST_FILTER_FILENAME}_tmpl
SECUREDAPP_REQUEST_FILTER_FILEPATH = ${SECUREDAPP_SRC_DIR}${SECUREDAPP_REQUEST_FILTER_FILENAME}
SECUREDAPP_REQUEST_FILTER_TMPL_FILEPATH = ${SECUREDAPP_DEST_DIR}${SECUREDAPP_REQUEST_FILTER_TMPL_FILENAME}
	
securedapp_tmpl: ${SECUREDAPP_SRC_DIR}
	@-echo Preparing Secured Application template ...
	@-echo ________________________________________________________________________________
	@-echo
	@-echo Copying configuration files ...
	@-cp -r ${SECUREDAPP_SRC_DIR} ${SECUREDAPP_DEST_DIR} 2> /dev/null
	@-echo Clear out SVN directories ...
	@-find ${SECUREDAPP_DEST_DIR} -name ".svn" -print | xargs /bin/rm -rf
	@-echo Remove unneeded files ...
	for i in ${SECUREDAPP_SURPLUS_FILES} ; do \
		rm -rf ${SECUREDAPP_DEST_DIR}$$i ; \
	done ;
	# Make an empty log file so that log directory is included in egg
	@-echo Make log directory ...
	mkdir ${SECUREDAPP_LOG_DEST_DIR}
	touch ${SECUREDAPP_LOG_FILEPATH}
	@-echo Making substitutions for ini file template variables ...
	sed -e s/'portNum = .*'/'portNum = %%\{portNumber}'/ \
	-e s/'baseURI = .*'/'baseURI = %%\{baseURI}'/ \
	-e s/'# Revision:.*'//g \
	-e s/'authN.redirectURI = .*'/'authN.redirectURI = %%{authnRedirectURI}'/ \
	-e s/'resultHandler.heading = .*'/'resultHandler.heading = %%{accessDeniedPageHeading}'/ \
	-e s/'pep.authzServiceURI = .*'/'pep.authzServiceURI = %%{authzServiceURI}'/ \
    -e s/'pep\.authzDecisionQuery\.issuerName = .*'/'pep\.authzDecisionQuery\.issuerName = %%\{authzDecisionQueryIssuerName}'/ \
    -e s/'pep\.authzDecisionQuery\.issuerFormat = .*'/'pep\.authzDecisionQuery\.issuerFormat = %%\{authzDecisionQueryIssuerFormat}'/ \
	-e s/'authkitCookieSecret =.*'/'authkitCookieSecret = %%\{authkitCookieSecret}'/ \
	-e s/'beaker\.session\.secret =.*'/'beaker\.session\.secret = %%\{beakerSessionCookieSecret}'/ \
	-e s/'authkit.openid.session.secret = .*'/'authkit.openid.session.secret = %%\{openidRelyingPartyCookieSecret}'/ \
	-e s/'testConfigDir = .*'// \
	-e s/testConfigDir/here/g \
	-e s/\(os\.path\.join\(\'%\(here\)s\'/\(os.path.join\(\'%%\{outputDir}\'/ \
		${SECUREDAPP_INI_FILEPATH_TMP} > ${SECUREDAPP_INI_TMPL_FILEPATH}
	rm -f ${SECUREDAPP_INI_FILEPATH_TMP}
	@-echo "Make template for ${SECUREDAPP_REQUEST_FILTER_FILENAME} ..."
	sed -r -e s/'http:\/\/localhost:7080\/'/'%%\{baseURI}'/ \
		${SECUREDAPP_REQUEST_FILTER_FILEPATH} > ${SECUREDAPP_REQUEST_FILTER_TMPL_FILEPATH}
	@-echo
	@-echo Create PKI directory and copying files ...
	-mkdir ${SECUREDAPP_PKI_DEST_DIR}
	cp ${SERVER_CERT_SRC_FILEPATH} ${SECUREDAPP_PKI_DEST_DIR}
	cp ${SERVER_KEY_SRC_FILEPATH} ${SECUREDAPP_PKI_DEST_DIR}
	-mkdir ${SECUREDAPP_CA_DEST_DIR}
	cp ${CA_SRC_DIR}* ${SECUREDAPP_CA_DEST_DIR}
	@-echo
	@-echo Done.
	
securedapp_tmpl_clean:
	@-echo Clearing Secured App template ...
	rm -rf ${SECUREDAPP_DEST_DIR}

# Authorisation Service Template Settings
AUTHZ_SERVICE_DIRNAME = authorisationservice/
AUTHZ_SERVICE_SRC_DIR = ${TEST_CONFIG_SRC_DIR}${AUTHZ_SERVICE_DIRNAME}
AUTHZ_SERVICE_DEST_DIR = ${DEST_DIR}${AUTHZ_SERVICE_DIRNAME}
AUTHZ_SERVICE_INI_FILENAME = authorisation-service.ini
AUTHZ_SERVICE_INI_FILEPATH_TMP = ${AUTHZ_SERVICE_DEST_DIR}${AUTHZ_SERVICE_INI_FILENAME}
AUTHZ_SERVICE_INI_TMPL_FILEPATH = ${AUTHZ_SERVICE_INI_FILEPATH_TMP}_tmpl
AUTHZ_SERVICE_FILES = ${AUTHZ_SERVICE_INI_FILENAME} pip-mapping.txt policy.xml \
	public authorisationserviceapp.py
AUTHZ_SERVICE_PKI_DEST_DIR = ${AUTHZ_SERVICE_DEST_DIR}pki/
AUTHZ_SERVICE_CA_DEST_DIR = ${AUTHZ_SERVICE_PKI_DEST_DIR}ca/
AUTHZ_SERVICE_LOG_DEST_DIR = ${AUTHZ_SERVICE_DEST_DIR}log/
AUTHZ_SERVICE_LOG_FILEPATH = ${AUTHZ_SERVICE_LOG_DEST_DIR}service.log


authorisation_service_tmpl:
	@-echo Preparing Authorisation Service template ...
	@-echo ________________________________________________________________________________
	@-echo
	@-echo Copying test ini file and other configuration files ...
	mkdir ${AUTHZ_SERVICE_DEST_DIR}
	for i in ${AUTHZ_SERVICE_FILES}; do \
		cp -r ${AUTHZ_SERVICE_SRC_DIR}$$i ${AUTHZ_SERVICE_DEST_DIR} ; \
	done ;
	@-echo Making substitutions for template variables ...
	sed -e s/'# Description:.*'/'# Description: Paster ini file for SAML\/XACML based Authorisation Service'/ \
	-e s/'saml\.mountPath.*'/'saml.mountPath = %%\{mountPath\}'/ \
	-e s/'samlIssuerName =.*'/'samlIssuerName = %%\{issuerName}'/ \
	-e s/'samlIssuerFormat =.*'/'samlIssuerFormat = %%\{issuerFormat}'/ \
	-e s/'testConfigDir = .*'// \
	-e s/testConfigDir/here/g \
	-e s/\(os\.path\.join\(\'%\(here\)s\'/\(os.path.join\(\'%%\{outputDir}\',\ \'log\'/ \
	${AUTHZ_SERVICE_INI_FILEPATH_TMP} > ${AUTHZ_SERVICE_INI_TMPL_FILEPATH}
	rm -f ${AUTHZ_SERVICE_INI_FILEPATH_TMP}
	@-echo
	# Make an empty log file so that log directory is included in egg
	@-echo Make log directory ...
	mkdir ${AUTHZ_SERVICE_DEST_DIR}log
	touch ${AUTHZ_SERVICE_LOG_FILEPATH}
	@-echo Create PKI directory and copying files ...
	mkdir -p ${AUTHZ_SERVICE_CA_DEST_DIR}
	cp ${SERVER_CERT_SRC_FILEPATH} ${AUTHZ_SERVICE_PKI_DEST_DIR}
	cp ${SERVER_KEY_SRC_FILEPATH} ${AUTHZ_SERVICE_PKI_DEST_DIR}
	cp ${CA_SRC_DIR}* ${AUTHZ_SERVICE_CA_DEST_DIR}
	@-echo Clear out SVN directories ...
	@-find ${AUTHZ_SERVICE_DEST_DIR} -name ".svn" -print | xargs /bin/rm -rf
	@-echo
	@-echo Done.
	
authorisation_service_tmpl_clean:
	@-echo Clearing Authorisation Service template ...
	rm -rf ${AUTHZ_SERVICE_DEST_DIR}


# Attribute Service Template
ATTR_SERVICE_DIRNAME = attributeservice/
ATTR_SERVICE_SRC_DIR = ${TEST_CONFIG_SRC_DIR}attributeauthority/sitea/
ATTR_SERVICE_DEST_DIR = ${DEST_DIR}${ATTR_SERVICE_DIRNAME}
ATTR_SERVICE_INI_FILENAME = attribute-service.ini
ATTR_SERVICE_INI_FILEPATH_TMP = ${ATTR_SERVICE_DEST_DIR}${ATTR_SERVICE_INI_FILENAME}
ATTR_SERVICE_INI_TMPL_FILEPATH = ${ATTR_SERVICE_INI_FILEPATH_TMP}_tmpl
ATTR_SERVICE_FILES = ${ATTR_SERVICE_INI_FILENAME} public attributeauthorityapp.py
ATTR_SERVICE_STATIC_CONTENT_DEST_DIR = ${ATTR_SERVICE_DEST_DIR}public/
ATTR_SERVICE_PKI_DEST_DIR = ${ATTR_SERVICE_DEST_DIR}pki/
ATTR_SERVICE_CA_DEST_DIR = ${ATTR_SERVICE_PKI_DEST_DIR}ca/
ATTR_SERVICE_LOG_DEST_DIR = ${ATTR_SERVICE_DEST_DIR}log/
ATTR_SERVICE_LOG_FILEPATH = ${ATTR_SERVICE_LOG_DEST_DIR}service.log


attribute_service_tmpl:
	@-echo Preparing Attribute Service template ...
	@-echo ________________________________________________________________________________
	@-echo
	-mkdir ${ATTR_SERVICE_DEST_DIR}
	@-echo Copying content directories and files ...
	for i in ${ATTR_SERVICE_FILES}; do \
		cp -r ${ATTR_SERVICE_SRC_DIR}$$i ${ATTR_SERVICE_DEST_DIR} ; \
	done ;
	@-echo Making substitutions for template variables ...
	sed -e s/'# Description:.*'/'# Description: Paster ini file for SAML Attribute Service'/ \
	-e s/'dbConnectionString = .*'/'dbConnectionString = sqlite:\/\/\/%(here)s\/user.db'/ \
	-e s/'port = .*'/'port = %%\{portNumber}'/ \
	-e s/'saml\.soapbinding\.mountPath.*'/'saml.soapbinding.mountPath = %%\{mountPath\}'/ \
	-e s/'saml\.soapbinding\.issuerName.*'/'saml.soapbinding.issuerName = %%\{issuerName}'/ \
	-e s/'saml\.soapbinding\.issuerFormat.*'/'saml\.soapbinding\.issuerFormat = %%\{issuerFormat}'/ \
	-e s/\(os\.path\.join\(\'%\(here\)s\'/\(os.path.join\(\'%%\{outputDir}\',\ \'log\'/ \
	${ATTR_SERVICE_INI_FILEPATH_TMP} > ${ATTR_SERVICE_INI_TMPL_FILEPATH}
	rm -f ${ATTR_SERVICE_INI_FILEPATH_TMP}
	@-echo
	@-echo Create PKI directory and copying files ...
	-mkdir ${ATTR_SERVICE_PKI_DEST_DIR}
	cp ${SERVER_CERT_SRC_FILEPATH} ${ATTR_SERVICE_PKI_DEST_DIR}
	cp ${SERVER_KEY_SRC_FILEPATH} ${ATTR_SERVICE_PKI_DEST_DIR}
	-mkdir ${ATTR_SERVICE_CA_DEST_DIR}
	cp ${CA_SRC_DIR}* ${ATTR_SERVICE_CA_DEST_DIR}
	# Make an empty log file so that log directory is included in egg
	@-echo Make log directory ...
	mkdir ${ATTR_SERVICE_DEST_DIR}log
	touch ${ATTR_SERVICE_LOG_FILEPATH}
	@-echo Copying test SQLite user database ...
	cp ${USERDB_FILEPATH} ${ATTR_SERVICE_DEST_DIR}
	@-echo Clear out SVN directories ...
	@-find ${ATTR_SERVICE_DEST_DIR} -name ".svn" -print | xargs /bin/rm -rf
	@-echo
	@-echo Done.
	
attribute_service_tmpl_clean:
	@-echo Clearing Attribute Service template ...
	rm -rf ${ATTR_SERVICE_DEST_DIR}
	

# Settings to create OpenID Provider template
OP_DIRNAME = openidprovider/
OP_SRC_DIR = ${INTEGRATION_TEST_DIR}${OP_DIRNAME}
OP_DEST_DIR = ${DEST_DIR}${OP_DIRNAME}
OP_INI_FILENAME = service.ini
OP_INI_FILEPATH_TMP = ${OP_DEST_DIR}openidprovider.ini
OP_INI_TMPL_FILEPATH = ${OP_DEST_DIR}${OP_INI_FILENAME}_tmpl
OP_PKI_DEST_DIR = ${OP_DEST_DIR}pki/
OP_CA_DEST_DIR = ${OP_PKI_DEST_DIR}ca/
OP_CONFIG_FILES = templates openidprovider.ini openidproviderapp.py public
OP_TMPL_DIR = ${OP_DEST_DIR}templates/
OP_SERVER_YADIS_TMPL_FILEPATH_TMP = ${OP_TMPL_DIR}serveryadis.xml
OP_SERVER_YADIS_TMPL_FILEPATH = ${OP_SERVER_YADIS_TMPL_FILEPATH_TMP}_tmpl
OP_YADIS_TMPL_FILEPATH_TMP = ${OP_TMPL_DIR}yadis.xml
OP_YADIS_TMPL_FILEPATH = ${OP_YADIS_TMPL_FILEPATH_TMP}_tmpl
OP_LOG_DEST_DIR = ${OP_DEST_DIR}log/
OP_LOG_FILEPATH = ${OP_LOG_DEST_DIR}service.log


openidprovider_tmpl:
	@-echo Preparing OpenID Provider template ...
	@-echo ________________________________________________________________________________
	@-echo
	@-echo Copying templates, CSS and graphics and ini file ...
	mkdir ${OP_DEST_DIR}
	mkdir ${OP_LOG_DEST_DIR}
	touch ${OP_LOG_FILEPATH}
	@-echo Copying files ...
	for i in ${OP_CONFIG_FILES} ; do \
		cp -r ${OP_SRC_DIR}$$i ${OP_DEST_DIR}; \
	done ;
	@-echo Making substitutions for template variables ...
	sed -e s/'portNum = .*'/'portNum = %%\{portNumber}'/ \
	-e s/'baseURI =.*'/'baseURI = %%\{baseURI}'/ \
	-e s/'testConfigDir = %(here)s\/\.\.\/\.\.\/config'// \
	-e s/testConfigDir/here/g \
	-e s/'# Revision:.*'// \
	-e s/'beaker.session.secret =.*'/'beaker.session.secret = %%\{beakerSessionCookieSecret}'/ \
	-e s/\(os\.path\.join\(\'%\(here\)s\'/\(os.path.join\(\'%%\{outputDir}\'/ \
	${OP_INI_FILEPATH_TMP} > ${OP_INI_TMPL_FILEPATH}
	rm -f ${OP_INI_FILEPATH_TMP}
	@-echo Making substitutions for Yadis templates ...
	sed -r -e /'<Service priority=\"(1|19|30|20)\">'/,/'<\/Service>'/d \
	-e s/'<\/XRD>'/'    %%\{serveryadisExtraServiceEndpoints}\n    <\/XRD>'/ \
		${OP_SERVER_YADIS_TMPL_FILEPATH_TMP} > ${OP_SERVER_YADIS_TMPL_FILEPATH}
	rm -f ${OP_SERVER_YADIS_TMPL_FILEPATH_TMP}
	sed -r -e /'<Service priority=\"(1|19|30|20)\">'/,/'<\/Service>'/d \
	-e s/'<\/XRD>'/'    %%\{yadisExtraServiceEndpoints}\n    <\/XRD>'/ \
		${OP_YADIS_TMPL_FILEPATH_TMP} > ${OP_YADIS_TMPL_FILEPATH}
	rm -f ${OP_YADIS_TMPL_FILEPATH_TMP}
	@-echo
	@-echo
	@-echo Copying test SQLite user database ...
	cp ${USERDB_FILEPATH} ${OP_DEST_DIR}
	@-echo
	@-echo Create PKI directory and copying files ...
	-mkdir ${OP_PKI_DEST_DIR}
	cp ${SERVER_CERT_SRC_FILEPATH} ${OP_PKI_DEST_DIR}
	cp ${SERVER_KEY_SRC_FILEPATH} ${OP_PKI_DEST_DIR}
	-mkdir ${OP_CA_DEST_DIR}
	cp ${CA_SRC_DIR}* ${OP_CA_DEST_DIR}
	@-echo Clear out SVN directories ...
	@-find ${OP_DEST_DIR} -name ".svn" -print | xargs /bin/rm -rf
	@-echo
	@-echo Done.
	
openidprovider_tmpl_clean:
	@-echo Clearing OpenID Provider template ...
	rm -rf ${OP_DEST_DIR}

	
clean: service_tmpl_clean securedapp_tmpl_clean \
		authorisation_service_tmpl_clean \
		attribute_service_tmpl_clean openidprovider_tmpl_clean

