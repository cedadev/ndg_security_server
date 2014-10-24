#!/usr/bin/env perl

sub perlFunc
{
    my $msg = shift;
    return $msg;
}

use Inline Python => <<'END';
def test2(a, b):
    return a, b

def pyTest(d, msg):
    import pdb;pdb.set_trace()
    print "d=%s" % d
    return {'AccessGranted':True, 'msg':"Access permitted"}
END

my %hash = (a => 0, b => 1);
my $msg = "hello";
my $res = pyTest(\%hash, $msg);
for my $key (keys %{$res})
{
    print "$key => ${$res}{$key}\n";
}
