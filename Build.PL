#
# $Id: Build.PL,v 1.1 2004/01/21 22:23:03 james Exp $
#

use Module::Build;

my $build = Module::Build->new(
	module_name         => 'Cisco::ACL',
    dist_version_from   => 'lib/Cisco/ACL.pm',
	license             => 'perl',
    create_makefile_pl  => 'passthrough',
    create_readme       => 1,
    requires            => {
        Class::MethodMaker => 0,
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
