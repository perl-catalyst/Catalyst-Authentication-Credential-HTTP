use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Catalyst::Plugin::Authentication::Credential::HTTP',
    requires           => {
        'perl'                             => '5.8.1',
        'Catalyst'                         => '5.49',
        'Catalyst::Plugin::Authentication' => 0,
        'String::Escape'                   => 0,
        'URI::Escape'                      => 0,
        'Test::MockObject'                 => '1.01',
        'Test::Exception'                  => 0,
        'Data::UUID'                       => 0.11
    },
    create_readme => 1,
    sign          => 0,
);
$build->create_build_script;

