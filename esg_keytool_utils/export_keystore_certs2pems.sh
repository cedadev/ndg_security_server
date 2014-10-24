#!/bin/bash
#
# Script to export all the certificates from Java key store to PEM format
# 
# @author P J Kershaw 04/08/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD
#
# $Id$
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

if [ -z "$keystore" ]; then
    echo "Missing 'keystore' setting from config file." >&2;
    echo $usage >&2 ;
    exit 1;
fi

# Check output directory setting
if [ -z "$export_dir" ]; then
    echo "Missing 'export_dir' setting from config file or value is null." >&2;
    echo $usage >&2 ;
    exit 1;

elif [ ! -d "export_dir" ]; then
    # Attempt to create path
    mkdir -p $export_dir
fi

# Keystore password may be retrieved from stdin
if [ "$keystore_passwd_from_stdin" ]; then
    # Read from stdin
    read -t 60 -p "Keystore password: " -s keystore_passwd ;
    echo ;
fi

# Check password is longer than 6 chars but skip if no password was set at
# all - this is legal.
if [ "$keystore_passwd" ] && [ ${#keystore_passwd} -lt 6 ]; then
    echo "keystore password must be longer than 6 characters." >&2 ;
    exit 1;
fi

# Temporary file to collect stderr from keytool
tmp_error_filepath=$(tempfile)
if [ -z "$aliases" ]; then
    # Get aliases for all the stored certificates
    # (Needs alternate invocations based on whether a password is set or not)
    if [ -z "$keystore_passwd" ]; then
        # Use echo to pipe in a null password at the prompt
        aliases=$(echo|keytool -list -keystore $keystore $keystore_passwd \
                2> $tmp_error_filepath | \
                grep trustedCertEntry | awk -F, '{print $1}')
    else
        aliases=$(keytool -list -keystore $keystore -storepass $keystore_passwd \
                2> $tmp_error_filepath | \
                grep trustedCertEntry| awk -F, '{print $1}')
    fi
    
    # Collected stderr from keytool
    tmp_file_output=$(< $tmp_error_filepath)
    rm -f $tmp_error_filepath
    
    # Check again to flag 'keytool -list' operation failed
    if [ -z "$aliases" ]; then
        echo No aliases found for keystore $keystore. Error output is: "$tmp_file_output" >&2 ;
        rm -f $(tempfile)
        exit 1;  
    fi
fi

# Temporary directory for DER file intermediate output
tmp_dir=$(mktemp -d)

# Export based on alias
for alias in $aliases; do
    # Export as DER format cert
    der_file="$tmp_dir/${alias}.der"
    if [ -z "$keystore_passwd" ]; then
        # Use echo to pipe in a null password at the prompt
        echo | keytool -export -alias "$alias" -keystore $keystore \
            $keystore_passwd -file "$der_file" 2> /dev/null
    else
        keytool -export -alias "$alias" -keystore $keystore -storepass \
            $keystore_passwd -file "$der_file" 2> /dev/null
    fi
    
    # Find out the hash and use this to name the exported PEM file
    cert_hash=$(openssl x509 -inform DER -in "$der_file" -noout -hash)
    if [ $? != "0" ]; then
        echo "Error calculating hash for certificate $der_file" >&2 ;
        break ;  
    fi 
           
    pem_file="$export_dir/${cert_hash}.0"
    
    # Convert exported file to PEM
    openssl x509 -inform DER -in "$der_file" -outform PEM -out "$pem_file"
done

rm -rf $tmp_dir ;
echo "Certificates exported from keystore $keystore to $export_dir." ;
exit 0 ;