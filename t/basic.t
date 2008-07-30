#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 22;
use Test::MockObject::Extends;
use Test::MockObject;
use Test::Exception;
use HTTP::Headers;

my $m; BEGIN { use_ok($m = "Catalyst::Authentication::Credential::HTTP") }
can_ok( $m, "authenticate" );
can_ok( $m, "authorization_required_response" );
my $req = Test::MockObject->new;
my $req_headers = HTTP::Headers->new;
$req->set_always( headers => $req_headers );
my $res = Test::MockObject->new;
my $status;
$res->mock(status => sub { $status = $_[1] });
my $content_type;
$res->mock(content_type => sub { $content_type = $_[1] });
my $body;
my $headers;
#$res->mock(headers => sub { use Data::Dumper; warn Dumper(\@_); $headers = $_[1]; });
$res->mock(body => sub { $body = $_[1] });
my $res_headers = HTTP::Headers->new;
$res->set_always( headers => $res_headers );
my $realm = Test::MockObject->new;
my $find_user_opts;
my $user = Test::MockObject->new;
my $user_pw;
$user->mock( check_password => sub { $user_pw = $_[1]; return 1; } );
$realm->mock( find_user => sub { $find_user_opts = $_[1]; return $user; });
$realm->mock( name => sub { 'foo' } );
my $c = Test::MockObject->new;
my $cache = Test::MockObject->new;
$cache->mock(set => sub { shift->{$_[0]} = $_[1] });
$cache->mock(get => sub { return shift->{$_[0]} });
$c->mock(cache => sub { $cache });
$c->mock(debug => sub { 0 });
my @login_info;
$c->mock( login => sub { shift; @login_info = @_; 1 } );
my $authenticated = 0;
$c->mock( set_authenticated => sub { $authenticated++; } );
$c->set_always( config => {} );
$c->set_always( req => $req );
$c->set_always( res => $res );
$c->set_always( request => $req );
$c->set_always( response => $res );
my $config = { type => 'any' };
my $raw_self = $m->new($config, $c, $realm);
my $self = Test::MockObject::Extends->new( $raw_self );
eval {
    $self->authenticate($c, $realm);
};
is($@, $Catalyst::DETACH, 'Calling authenticate for http auth without header detaches');
$req_headers->authorization_basic( qw/foo bar/ );
ok($self->authenticate($c, $realm), "auth successful with header");
is($authenticated, 1, 'authenticated once');
is($user_pw, 'bar', 'password delegated');
is_deeply( $find_user_opts, { username => 'foo'}, "login delegated");
$req_headers->clear;
$c->clear;
throws_ok {
    $self->authenticate( $c, $realm );
} qr/^ $Catalyst::DETACH $/x, "detached on no authorization required with bad auth";
is( $status, 401, "401 status code" );
is( $content_type, 'text/plain' );
is( $body, 'Authorization required.' );
like( ($res_headers->header('WWW-Authenticate'))[0], qr/^Digest/, "WWW-Authenticate header set: digest");
like( ($res_headers->header('WWW-Authenticate'))[0], qr/realm="foo"/, "WWW-Authenticate header set: digest realm");
like( ($res_headers->header('WWW-Authenticate'))[1], qr/^Basic/, "WWW-Authenticate header set: basic");
like( ($res_headers->header('WWW-Authenticate'))[1], qr/realm="foo"/, "WWW-Authenticate header set: basic realm");

throws_ok {
    $self->authenticate( $c, $realm, { realm => 'myrealm' }); # Override realm object's name method by doing this.
} qr/^ $Catalyst::DETACH $/x, "detached on no authorization required with bad auth";
is( $status, 401, "401 status code" );
is( $content_type, 'text/plain' );
is( $body, 'Authorization required.' );
TODO: {
    local $TODO = 'This should work, it (or something very like it) used to work';
    like( ($res_headers->header('WWW-Authenticate'))[0], qr/realm="myrealm"/, "WWW-Authenticate header set: digest realm overridden");
    like( ($res_headers->header('WWW-Authenticate'))[1], qr/realm="myrealm"/, "WWW-Authenticate header set: basic realm overridden");
}
