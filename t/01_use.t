#
# $Id$
#

use strict;
use warnings;

use Test::More tests => 2;

use_ok('Cisco::ACL');
is($Cisco::ACL::VERSION, '0.12', 'check module version');

#
# EOF
