#!/usr/bin/env perl
use strict;

use Storable qw(freeze thaw);

my @roles = ('coapec', 'badcuser');
my %session = (
        h => 'https://localhost/SessionManager',
        sid => 'abcdef1234567890',
        u => 'pjkersha',
        org => 'BADC',
        roles => \@roles,
);

my $serialisedSess = freeze(\%session);

use Crypt::CBC;
my $encryptionKey = 'abcdef0123456789';
my $cipher = new Crypt::CBC(-key=>$encryptionKey, -cipher=>'Blowfish', -salt=>1);

my $encrSerialisedSess = $cipher->encrypt_hex($serialisedSess);
print "encrSerialisedSess = ".$encrSerialisedSess."\n";
my $decrSerialisedSess = $cipher->decrypt_hex($encrSerialisedSess);
my $deserialisedSess = thaw($decrSerialisedSess);
foreach my $key (keys %{$deserialisedSess})
{
    print "$key=$deserialisedSess->{$key}\n";
}
