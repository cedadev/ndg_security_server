#!/bin/bash
#
# Script to update/create a Java key store and add certificates via MyProxy
# provisioning
#
# $ update_trust_roots --config-file=./update_trust_roots
#
# A configuration file is required of the form:
#
# # List of MyProxy servers - quote the list
# myproxy_servers="myproxy.somewhere.ac.uk myproxy.somewhere-else.ac.uk"
#
# # file path for Java Key store to be created/updated
# keystore="./keystore"
#
# # Java Key store password
# keystore_passwd=123456
# 
# @author P J Kershaw 03/02/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD
#
# $Id:$

cmdline_opt=`getopt -o hc: --long help,config-file:: -n "$0" -- "$@"`

usage="Usage: $(basename $0) [-h|--help] [-c|--config-file filename]"
if [ $? != 0 ] ; then
    echo $usage >&2 ;
    exit 1 ;
fi

# Note the quotes around `$cmdline_opt': they are essential!
eval set -- "$cmdline_opt"

while true ; do
    case "$1" in
        -h|--help) echo $usage ; exit 0 ;;
        -c|--config-file) config_filepath=$2 ; shift 2 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

if [ -z $config_filepath ]; then
    echo "Missing config file path setting." >&2; 
    echo $usage >&2 ;
    exit 1;
fi

# Read config file settings
. $config_filepath
for server in $myproxy_servers; do
    echo Retrieving trust roots from $server ...;
    myproxy-get-trustroots -s $server;
done

if [ -z $keystore ]; then
    echo "Missing 'keystore' setting from config file." >&2;
    echo $usage >&2 ;
    exit 1;
fi

# Keystore password may be retrieved from stdin
if [ -z $keystore_passwd ]; then
    # Read from stdin
    read -t 60 -p "Keystore password: " -s keystore_passwd ;
    echo ;
fi


if [ -z $keystore_passwd ]; then 
    echo "No keystore password set: exiting ..." >&2 ;
    exit 1;
    
elif [ ${#keystore_passwd} -lt 6 ]; then
    echo "keystore password must be longer than 6 characters." >&2 ;
	exit 1;
fi


# Set the location of the trust root directory from which certificates will
# be retrieved
username=$(whoami)
if [ $username = "root" ]; then
    trust_roots_dir=/etc/grid-security/certificates
else
    trust_roots_dir=${HOME}/.globus/certificates
fi

# Get certificates from updated trust roots directory
cert_files=$(find $trust_roots_dir -name "*.0" -print)

for cert_file in $cert_files; do
    cert_hash=$(echo $(basename $cert_file)|awk -F'.' '{print $1}') ;
    der_file="$tmp_dir$cert_hash.der" ;
    
    # Convert to DER format for ingest into keystore
    openssl x509 -inform pem -in $cert_file -outform der -out $der_file ;
    if [ -f $keystore ]; then
        keytool -delete -alias $cert_hash -keystore $keystore \
            -storepass $keystore_passwd 2>&1 > /dev/null ;
    fi
    
    keytool -import -alias $cert_hash -file $der_file -keystore $keystore \
        -storepass $keystore_passwd -noprompt ;
    rm -f $der_file ;
done
