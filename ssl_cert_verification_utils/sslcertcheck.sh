#!/bin/bash
#
# Get an SSL certificate from a server and verify it against a set of trusted CA
# certificates and check it for time validity. e.g. check mulitiple services:
#
# $ sslcertcheck.sh -c "somewhere.ac.uk:443 somewhereelse.ac.uk:6000" -p ./ca-dir
#
# It outputs the status for each connection made and exits with 1 if any of them
# fails; exits with 0 if all succeed.  To check a single connection e.g.
#
# $ sslcertcheck.sh --connect someservice.ac.uk:8443 --CApath ./ca-dir
#
# - this example uses alternative long form for command line options.
#
# Author: P J Kershaw 
#
# Date: 14/01/2011
#
# Copyright: (C) 2011 STFC
#
# License: BSD
#
# $Id$
cmdline_opt=`getopt -o hc:p:d: --long help,connect:,CApath:days-expiry-from-now:: -n "$0" -- "$@"`

usage="Usage: $(basename $0) [-h|--help] [-c|--connect \"host1:port1 host2:port2 ... hostN:portN\"] [-p|--CApath dir]"
if [ $? != 0 ] ; then
    echo $usage >&2 ;
    exit 1 ;
fi

# Note the quotes around `$cmdline_opt': they are essential!
eval set -- "$cmdline_opt"

while true ; do
    case "$1" in
        -h|--help) echo $usage ; exit 0 ;;
        -c|--connect) connect_strings=$2 ; shift 2 ;;
        -p|--CApath) ca_dir=$2 ; shift 2 ;;
        -d|--days-expiry-from-now) days_expiry_from_now=$2 ; shift 2 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

if [ -z "$connect_strings" ]; then
    echo No connection string set >&2 ;
    echo $usage >&2 ;
    exit 1 ;
fi

if [ "$ca_dir" ]; then
    verify_arg="-CApath $ca_dir"
fi

if [ "$days_expiry_from_now" ]; then
    # Use bc to allow for decimal days
    secs_expiry_from_now=$(echo "$days_expiry_from_now * 86400"|bc -l) ;
else
    secs_expiry_from_now=0 ; 
fi

# Check each connection in turn ...
exit_code=0;
for connect_string in $connect_strings; do
    echo -n "Checking \"$connect_string\"" ;
    output=$(echo | openssl s_client -connect $connect_string $verify_arg 2>&1)
    openssl_exit_code=$?
    if [ "$openssl_exit_code" -ne "0" ]; then
        echo ": $output" >&2 ;
        exit_code=1 ;
        continue ;
    fi

    verify_return_msg=$(echo "$output" | grep "Verify return code:"|awk -F': ' '{print $2}')
    verify_return_code=$(echo $verify_return_msg | awk '{print $1}')
    cert_output=$(echo "$output" | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -noout -subject -enddate)

    subject=$(echo "$cert_output" | grep subject | awk -F'subject= ' '{print $2}')
    expiry_date=$(echo "$cert_output" | grep notAfter | awk -F'notAfter=' '{print $2}')

    expiry_date_secs=$(date --date="$expiry_date" +%s)
    current_date_secs=$(date +%s)
    test_date_secs=$(echo $current_date_secs + $secs_expiry_from_now | bc -l)

    echo -n ", certificate \"$subject\": " ;
    if [ "$verify_return_code" -ne 0 ]; then
        echo $verify_return_msg ;
        exit_code=1 ;
    fi
 
    if [ "$expiry_date_secs" -lt "$test_date_secs" ]; then
        test_date=$(date -d "1970-01-01 $test_date_secs sec GMT")
        echo certificate expires before $test_date ;
        exit_code=1 ;
    fi

    if [ "$exit_code" -eq "0" ]; then
        echo "OK" ;
    fi
done ;

exit $exit_code ;
