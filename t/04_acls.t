#
# $Id$
#

use strict;
use warnings;

use Test::More 'no_plan';
use Test::Exception;

my $package = 'Net::ACL::Cisco';

use_ok($package);

my $acl;
lives_ok {
    $acl = $package->new;
} 'create an ACL object';
isa_ok($acl, $package);

# these expected results of these tests are taken directly from the output
# of Chris De Young's original ACL Maker CGI.  Each tuple consists of 7
# elements: a 1 or 0 for permit/deny, the source address, the source port,
# the dest address, the dest port, the protocol, and the expected output.
my @tests;
{

    no warnings 'qw'; # lets us put commas in our words

    @tests = (

        [ qw|1 10.1.1.1 any 10.1.2.1 any tcp|,
          [
            'permit tcp host 10.1.1.1 host 10.1.2.1',
          ],
        ],

        [ 1, [ '10.10.10.10/8', '45.45.45.45' ], 34, '192.168.1.1/27', 'any', 'udp',
          [
            'permit udp 10.0.0.0 0.255.255.255 eq 34 192.168.1.0 0.0.0.31',
            'permit udp host 45.45.45.45 eq 34 192.168.1.0 0.0.0.31',
          ],
        ],

        [ 0, [ '10.94.98.0/24', '10.94.99.0/24' ], 'any', '10.160.1.125', 21937, 'tcp',
          [
            'deny tcp 10.94.98.0 0.0.0.255 host 10.160.1.125 eq 21937',
            'deny tcp 10.94.99.0 0.0.0.255 host 10.160.1.125 eq 21937',
          ],
        ],

    );

}

for( @tests ) {
    my($permit, $src_addr, $src_port, $dst_addr, $dst_port,
       $proto, $expected) = @{ $_ };
    $acl->permit($permit);
    $acl->src_addr($src_addr);
    $acl->src_port($src_port);
    $acl->dst_addr($dst_addr);
    $acl->dst_port($dst_port);
    $acl->protocol($proto);
    my $gotback = $acl->lists;
    is_deeply($gotback, $expected, "$proto from $src_addr port $src_port to $dst_addr port $dst_port");
    $gotback = Net::ACL::Cisco->new(
        permit   => $permit,
        src_addr => $src_addr,
        src_port => $src_port,
        dst_addr => $dst_addr,
        dst_port => $dst_port,
        protocol => $proto,
    )->lists;
    is_deeply($gotback, $expected, "$proto from $src_addr port $src_port to $dst_addr port $dst_port");
}

#
# EOF
