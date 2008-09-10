#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 24;
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
$res->mock(body => sub { $body = $_[1] });
my $res_headers = HTTP::Headers->new;
$res->set_always( headers => $res_headers );
my $user = Test::MockObject->new;
$user->mock(get => sub { return shift->{$_[0]} });
my $find_user_opts;
my $realm = Test::MockObject->new;
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

sub new_self {
    my $config = { @_ };
    my $raw_self = $m->new($config, $c, $realm);
    return Test::MockObject::Extends->new( $raw_self );
}

# Normal auth, simple as possible.
# No credentials
my $self = new_self( type => 'any', password_type => 'clear', password_field => 'password' );
throws_ok {
    $self->authenticate( $c, $realm );
} qr/^ $Catalyst::DETACH $/x, 'Calling authenticate for http auth without header detaches';
$user->{password} = 'bar';

# Wrong credentials
$req_headers->authorization_basic( qw/foo quux/ );
throws_ok {
    $self->authenticate( $c, $realm );
} qr/^ $Catalyst::DETACH $/x, 'Calling authenticate for http auth without header detaches';

# Correct credentials
$req_headers->authorization_basic( qw/foo bar/ );
ok($self->authenticate($c, $realm), "auth successful with header");
is($authenticated, 1, 'authenticated once');
is_deeply( $find_user_opts, { username => 'foo'}, "login delegated");

# Test all the headers look good.
$req_headers->clear;
$res_headers->clear;
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

$res_headers->clear;
# Check password_field works
{
    my $self = new_self( type => 'any', password_type => 'clear', password_field => 'the_other_password' );
    local $user->{password} = 'bar';
    local $user->{the_other_password} = 'the_other_password';
    $req_headers->authorization_basic( qw/foo the_other_password/ );
    ok($self->authenticate($c, $realm), "auth successful with header and alternate password field");
    $c->clear;
    $req_headers->authorization_basic( qw/foo bar/ );
    throws_ok {
        $self->authenticate( $c, $realm );
    } qr/^ $Catalyst::DETACH $/x, "detached on bad password (different password field)";
}

$req_headers->clear;
$res_headers->clear;
throws_ok {
    $self->authenticate( $c, $realm, { realm => 'myrealm' }); # Override realm object's name method by doing this.
} qr/^ $Catalyst::DETACH $/x, "detached on no authorization supplied, overridden realm value";
is( $status, 401, "401 status code" );
is( $content_type, 'text/plain' );
is( $body, 'Authorization required.' );
like( ($res_headers->header('WWW-Authenticate'))[0], qr/realm="myrealm"/, "WWW-Authenticate header set: digest realm overridden");
like( ($res_headers->header('WWW-Authenticate'))[1], qr/realm="myrealm"/, "WWW-Authenticate header set: basic realm overridden");

