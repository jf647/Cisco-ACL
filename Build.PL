#
# $Id: Build.PL,v 1.1 2003/12/28 23:24:18 james Exp $
#

use Module::Build;

my $build = Module::Build->new(
	module_name         => 'Net::ACL::Cisco',
    dist_version_from   => 'lib/Net/ACL/Cisco.pm',
	license             => 'perl',
    create_makefile_pl  => 'passthrough',
    create_readme       => 1,
    requires            => {
        Class::MethodMaker => '1.12',
        Params::Validate   => '0.65',
    },
    build_requires      => {
        Test::More      => 0,
        Test::Exception => 0,
    },
);

$build->create_build_script;

#
# EOF
