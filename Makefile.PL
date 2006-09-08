use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'         => 'Catalyst::Plugin::Authentication::Credential::HTTP',
    'VERSION_FROM' => 'lib/Catalyst/Plugin/Authentication/Credential/HTTP.pm',
    'PREREQ_PM'    => {
        'Catalyst'                         => '5.49',
        'Catalyst::Plugin::Authentication' => 0,
        'Data::UUID'                       => '0.11',
        'String::Escape'                   => 0,
        'Test::Exception'                  => 0,
        'Test::MockObject'                 => '1.01',
        'URI::Escape'                      => 0,
    },
    'INSTALLDIRS' => 'site',
    'EXE_FILES'   => [],
    'PL_FILES'    => {},
    'SIGN'        => 1,
);
