#!/bin/sh
export CURLOPT_SSLCERT=proxy.pem
export CURLOPT_SSLKEY=proxy.pem
#export CURLOPT_CAINFO=
export CURLOPT_CAPATH=./ca
export CURLOPT_COOKIEFILE=./cookie.txt
export CURLOPT_COOKIEJAR=./cookie.txt
export CURLOPT_VERBOSE=1
export CURLOPT_FOLLOWLOCATION=1
#export CURLOPT_MAXREDIRS=
