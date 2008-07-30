use inc::Module::Install 0.65;

name 'Catalyst-Authentication-Credential-HTTP';
all_from 'lib/Catalyst/Authentication/Credential/HTTP.pm';

requires 'Catalyst::Runtime';
requires 'Catalyst::Plugin::Authentication' => '0.10000';
requires 'Data::UUID' => '0.11';
requires 'String::Escape';
requires 'Test::Exception';
requires 'Test::MockObject';
requires 'URI::Escape';

auto_install;
WriteAll;

