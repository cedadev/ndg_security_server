#
# NERC DataGrid Project
#
# @author P J Kershaw 15/03/07
#
# Make all eggs
#
# @copyright: (C) 2007 STFC
#
# @license: BSD - LICENSE file
#
# $Id$
EGG_DIRS=ndg_security_common ndg_security_client ndg_security_server \
ndg_security_test ndg_security

# Override on the command line for alternative path
PYTHON=python

Eggs:
	@echo "Running setup bdist_egg in these directories ${EGG_DIRS} ..."
	@-for dir in ${EGG_DIRS}; do \
		cd $$dir; \
		${PYTHON} setup.py bdist_egg; \
		${PYTHON} setup.py sdist; \
		cd ..; \
	done;

develop:
	@-for dir in ${EGG_DIRS}; do \
		cd $$dir; \
		${PYTHON} setup.py develop; \
		cd ..; \
	done;

clean:
	@-for dir in ${EGG_DIRS}; do \
		cd $$dir; \
		rm -f dist/*.egg; \
		rm -f dist/*.tar.gz; \
		rm -rf *.egg-info; \
		rm -rf build; \
		cd ..; \
	done;

replace: clean eggs

# Convenient alias
force: replace

#NDG_EGG_DIST_USER=
#NDG_EGG_DIST_HOST=
#NDG_EGG_DIST_DIR=

install_eggs: Eggs
	@echo "Installing eggs to ${NDG_EGG_DIST_HOST}:${NDG_EGG_DIST_DIR} ..."
	scp ndg_security*/dist/*.egg ${NDG_EGG_DIST_USER}@${NDG_EGG_DIST_HOST}:${NDG_EGG_DIST_DIR}
	scp ndg_security*/dist/*.tar.gz ${NDG_EGG_DIST_USER}@${NDG_EGG_DIST_HOST}:${NDG_EGG_DIST_DIR}
	ssh ${NDG_EGG_DIST_USER}@${NDG_EGG_DIST_HOST} "chown ${NDG_EGG_DIST_USER}:cedadev ${NDG_EGG_DIST_DIR}/ndg_security*.egg"
	ssh ${NDG_EGG_DIST_USER}@${NDG_EGG_DIST_HOST} "chown ${NDG_EGG_DIST_USER}:cedadev ${NDG_EGG_DIST_DIR}/ndg_security*.tar.gz"

# Make ZSI stubs from Session Manager WSDL
SM_ZSI_STUB_DIRS=./ndg_security_server/ndg/security/server/zsi/sessionmanager \
				 ./ndg_security_common/ndg/security/common/zsi/sessionmanager

sm_zsi_wsdl_stubs:
	@-for dir in ${SM_ZSI_STUB_DIRS}; do \
		cd $$dir && make && cd ../../../../../..; \
	done;

# Make ZSI stubs from Attribute Authority WSDL
AA_ZSI_STUB_DIRS=./ndg_security_server/ndg/security/server/zsi/attributeauthority \
				 ./ndg_security_common/ndg/security/common/zsi/attributeauthority
				 
aa_zsi_wsdl_stubs:
	@-for dir in ${AA_ZSI_STUB_DIRS}; do \
		cd $$dir && make && cd ../../../../../..; \
	done;

# Make all ZSI stubs for NDG security
zsi_wsdl_stubs: sm_zsi_wsdl_stubs aa_zsi_wsdl_stubs


# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_OUTDIR=../documentation/epydoc
EPYDOC_NAME='NDG Security'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_FRAMES_OPT=--no-frames
epydoc:
	${EPYDOC} ./ndg_security_*/ndg -o ${EPYDOC_OUTDIR} \
	--name ${EPYDOC_NAME} ${EPYDOC_FRAMES_OPT} --include-log --graph=all -v \
	--exclude=nosetests.* > ${EPYDOC_LOGFILE}

# Install epydoc on web server - set environment variables in a setup script
# or one the command line and use the -e option for make
NDG_EPYDOC_USER=
NDG_EPYDOC_HOST=
NDG_EPYDOC_DIR=
install_epydoc:
	scp -r ${EPYDOC_OUTDIR} \
	${NDG_EPYDOC_USER}@${NDG_EPYDOC_HOST}:${NDG_EPYDOC_DIR}
	
# Generate SysV init scripts for Twisted based services
init_scripts:
	cd ./ndg_security_server/ndg/security/server/share && make generateScripts

