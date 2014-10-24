#!/usr/bin/env perl
use strict;
use Log::Log4perl;
use AppConfig qw/:argcount/;
Log::Log4perl::init(qw "/var/www/cgi-bin/NDG/Security/log/ndg-security.log");
#$ENV{'NDGSEC_PERL_CLNT_LOGFILE'});
print $ENV{'HOME'}."\n";
