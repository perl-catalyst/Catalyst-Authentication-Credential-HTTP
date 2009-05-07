use inc::Module::Install 0.87;

name 'Catalyst-Authentication-Credential-HTTP';
all_from 'lib/Catalyst/Authentication/Credential/HTTP.pm';

requires 'Catalyst::Runtime';
requires 'Catalyst::Plugin::Authentication' => '0.10000';
requires 'Data::UUID' => '0.11';
requires 'String::Escape';
requires 'Test::Exception';
requires 'Test::MockObject';
requires 'URI::Escape';
requires 'Class::Accessor::Fast';

resources repository => 'http://dev.catalyst.perl.org/repos/Catalyst/Catalyst-Authentication-Credential-HTTP';

auto_install;
WriteAll;

