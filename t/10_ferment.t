#
# $Id$
#

use strict;
use warnings;

BEGIN {
    use Test::More;
    use Test::Exception;
    our $tests = 3;
    eval "use Test::NoWarnings";
    $tests++ unless( $@ );
    plan tests => $tests;
}

my $package = 'Cisco::ACL';

use_ok($package);

my @expected = qw|
    192.168.1.1
    192.168.1.2
    192.168.1.3
    192.168.1.4/30
    192.168.1.8
    192.168.1.9
    192.168.1.10
|;
my @gotback = Cisco::ACL::ferment('3232235785-3232235786', qw|192.168.1.1 192.168.1.2 192.168.1.3 192.168.1.4/30 192.168.1.8| );
is_deeply \@gotback, \@expected, 'ferment with defined range';

@expected = qw|
    192.168.1.1
    192.168.1.2
    192.168.1.3
    192.168.1.4/30
    192.168.1.8
|;
@gotback = Cisco::ACL::ferment('', qw|192.168.1.1 192.168.1.2 192.168.1.3 192.168.1.4/30 192.168.1.8| );
is_deeply \@gotback, \@expected, 'ferment with undefined range';

my $ip1 = Cisco::ACL::ip_to_decimal('192.168.0.0');
my $ip2 = Cisco::ACL::ip_to_decimal('192.168.255.255');
Cisco::ACL::ferment("$ip1-$ip2");
Cisco::ACL::ferment("$ip2-$ip1");

#
# EOF
