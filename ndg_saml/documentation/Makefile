#
# Makefile to generate epydoc documentation for the MyProxy Client Package
#
# NERC DataGrid Project
#
# @author P J Kershaw 15/12/08
#

# @copyright: (C) 2008 STFC
#
# @license: BSD - See LICENSE file in top-level directory
#
# $Id$

# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_INDIR=../ndg
EPYDOC_OUTDIR=.
EPYDOC_NAME='NERC DataGrid SAML 2.0'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_OPTS=--no-frames --include-log --graph=all -v
ZIP=zip
ZIP_OUTFILE=./documentation.zip
ZIP_INFILES=./*.*

epydoc:
	${EPYDOC} ${EPYDOC_INDIR} -o ${EPYDOC_OUTDIR} --name ${EPYDOC_NAME} \
	${EPYDOC_OPTS} > ${EPYDOC_LOGFILE}
	
zip:
	${ZIP} ${ZIP_OUTFILE} ${ZIP_INFILES}

clean:
	rm -f *.txt *.html *.gif *.png *.zip *.css *.js *.log
