#
# $Id$
#

use strict;
use warnings;

use Test::More tests => 2;

use_ok('Net::ACL::Cisco');
is($Net::ACL::Cisco::VERSION, 0.10, 'check module version');

#
# EOF
