#!/usr/bin/env perl

use strict;
use warnings;
use CGI;
#use ndgsecurity::ssoclient;
use NDG::Security::Client;

my $cgi = CGI->new();
my $cfgFilePath = "/var/www/cgi-bin/NDG/Security/conf/ndg-security-client.cfg";
my $session = eval {new NDG::Security::Client($cfgFilePath, $cgi)};

# Call Single Sign On handler
my $redirectHdr = $session->ssoHandler();
if ($redirectHdr)
{
    # A redirect header has created indicating the handler has received a response from
    # a Single Sign Service
    print $redirectHdr;
}
else
{
    # Create a form based on the WAYF address and encoded return to address formulated by
    # ssoHandler
    print $cgi->header('text/html');
    print $cgi->start_html('NDG Login'),
    $cgi->h1('NDG Login'),
    $cgi->start_form(-action=>$session->{wayfURI}),
    $cgi->hidden('r', $session->{b64encReturnToURL}), $cgi->br,
    $cgi->submit('NDG Login'),
    $cgi->end_form, $cgi->p,
    $cgi->hr;
    
    print $cgi->end_html;
}
    