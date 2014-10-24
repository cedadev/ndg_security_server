#
# ESG Download script wraps wget call with settings for ESG Security
#
# @author P J Kershaw 28/07/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - See top-level LICENCE file for licence details
#
# $Id$
cmdname=$(basename $0)
cmdline_opt=`getopt -o hO: --long help,output-document:,certificate:,private-key:,ca-directory:,save-cookies:: -n "$cmdname" -- "$@"`

esgDotDir=$HOME/.esg
defaultCertFile=$esgDotDir/credentials.pem
defaultPrivateKeyFile=$esgDotDir/credentials.pem
defaultCaDir=$esgDotDir/certificates
defaultCookieFile=$esgDotDir/cookies.txt
usage="Usage: $cmdname <data download URI> <options ...>\n
\n
Script for Earth System Grid data download.\n\n

   Options\n
       -h | --help\t\t\t\tDisplays usage\n
       -O | --output-document\t<filepath>\tLocation of output file (defaults to\n
       \t\t\t\t\tappropriate file name based on requested\n
       \t\t\t\t\tURI\n
       --certificate\t<certificate file>\tSSL certificate to authenticate with\n
       \t\t\t\t\t(PEM format).\n
       \t\t\t\t\tDefaults to X509_USER_PROXY or\n
       \t\t\t\t\tX509_USER_CERT if set, otherwise to\n 
       \t\t\t\t\t$defaultCertFile.  If\n
       \t\t\t\t\tusing X509_USER_PROXY,\n
       \t\t\t\t\tit must point to a file containing the\n
       \t\t\t\t\tconcatenated certificate and private\n
       \t\t\t\t\tkey files.\n
       --private-key\t<private key file>\tfile containing private key for SSL\n
       \t\t\t\t\tauthentication (PEM format) Defaults to\n
       \t\t\t\t\tX509_USER_PROXY or X509_USER_KEY if set,\n 
       \t\t\t\t\totherwise to\n
       \t\t\t\t\t$defaultPrivateKeyFile.\n
       --ca-directory\t<directory path>\tDirectory containing the trusted\n
       \t\t\t\t\tCA (Certificate Authority) certificates\n
       \t\t\t\t\tused to verify the identity of the\n
       \t\t\t\t\tserver (defaults to \n
       \t\t\t\t\t$defaultCaDir or may\n
       \t\t\t\t\tbe set from the X509_CERT_DIR\n
       \t\t\t\t\tenvironment variable).  The CA files can\n
       \t\t\t\t\tbe obtained by a call to MyProxy logon\n
       \t\t\t\t\tsaving 'trust roots' to the selected CA\n
       \t\t\t\t\tdirectory.\n
       --save-cookies\t<cookie file>\t\tSave cookies to this file.  The default\n
       \t\t\t\t\tlocation is\n
       \t\t\t\t\t$defaultCookieFile.
"

if [ $? != 0 ] ; then
    echo -e $usage >&2 ;
    exit 1 ;
fi

eval set -- "$cmdline_opt"

while true ; do
    case "$1" in
        -h|--help) echo -e $usage ; exit 0 ;;
        --certificate) certFile=$2 ; shift 2 ;;
        --private-key) privateKeyFile=$2 ; shift 2 ;;
        --ca-directory) caDir=$2 ; shift 2 ;;
        -O|--output-document) outputFile=$2 ; shift 2 ;;
        --save-cookies) cookieFile=$2 ; shift 2 ;;
        --) uri=$2 ; shift 1 ; break ;;
        *) echo "Error parsing command line" ; exit 1 ;;
    esac
done

if [ -z $uri ]; then
    echo "Error: missing download URI." >&2 ;
    echo -e $usage >&2 ;
    exit 1 ;
fi

# Set up default ESG config directory
if [ ! -d $esgDotDir ]; then
    mkdir $esgDotDir ;
fi
   
# Set-up trust root
if [ -z $caDir ]; then  
    if [ ${X509_CERT_DIR} ]; then
        caDir=${X509_CERT_DIR}
    else
        caDir=$defaultCaDir
    fi
fi

# Set-up client certificate and private key
if [ -z $certFile ]; then
    if [ ${X509_USER_PROXY} ]; then
        # This environment variable setting means both cert and key are 
        # concatenated together in the same file
        certFile=${X509_USER_PROXY}
        privateKeyFile=${X509_USER_PROXY}
        
    elif [ ${X509_USER_CERT} ]; then
        certFile=${X509_USER_CERT}    
    else
        certFile=$defaultCertFile   
    fi
    
    # No check for cert not set because this is a valid condition if the data 
    # requested is not secured.
fi

if [ -z $privateKeyFile ]; then
    if [ ${X509_USER_KEY} ]; then
        privateKeyFile=${X509_USER_KEY}
    else
        privateKeyFile=$defaultPrivateKeyFile
    fi
    
    # No check for key not set because this is a valid condition if the data 
    # requested is not secured
fi

# Set-up the cookie file path
if [ -z $cookieFile ]; then
    cookieFile=$defaultCookieFile
fi

if [ $outputFile ]; then
    outputFileSetting=--output-document=$outputFile
else
    outputFileSetting=
fi

# Make the call
wget \
 --ca-directory=$caDir \
 --certificate=$certFile \
 --private-key=$privateKeyFile \
 --keep-session-cookies \
 --save-cookies=$cookieFile \
 --cookies=on \
 --no-cache \
 $outputFileSetting \
 $uri
