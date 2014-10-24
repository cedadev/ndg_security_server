#!/usr/bin/env perl

use strict;
use warnings;
use CGI;

# TODO: remove for production - this is for debug only
use CGI::Carp qw/fatalsToBrowser/;

use NDG::Security::Client;

my $cgi = CGI->new();
#my $session = ndgsecurity::ssoclient->new($cgi);
my $cfgFilePath = "/var/www/cgi-bin/NDG/Security/conf/ndg-security-client.cfg";
my $session = eval {new NDG::Security::Client($cfgFilePath, $cgi)};
if ($@)
{
    print $cgi->header('text/html');
    print $cgi->start_html('NDG Secured Resource'),
    $cgi->h1('NDG Secured Resource'),
    "An error occured initialising the security configuration", $cgi->p,
    $cgi->hr;
    
    print $cgi->end_html;
}
else
{
    # Call Single Sign On handler
    my $redirectHdr = $session->ssoHandler();
    if ($redirectHdr)
    {
        # A redirect header has been created indicating 
        # 1) the handler has received a response from a Single Sign Service
        # or
        # 2) User is not logged in - redirecting to WAYF
        print $redirectHdr;
    }
    else
    {
        # Check access for this page
        my $dir = "/var/www/cgi-bin/";
        my $msg;
        
        my $accessDecision = $session->pep($dir);
        
        print $cgi->header('text/html');
        print $cgi->start_html('NDG Secured Resource'),
        $cgi->h1('NDG Secured Resource'),
        $accessDecision->{msg}, $cgi->p,
        $cgi->hr;
        
        print $cgi->end_html;
    }
}