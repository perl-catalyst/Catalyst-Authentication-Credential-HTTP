#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 13;
use Test::MockObject::Extends;
use Test::MockObject;
use HTTP::Headers;


my $m; BEGIN { use_ok($m = "Catalyst::Plugin::Authentication::Credential::HTTP") }

can_ok( $m, "authenticate_http" );
can_ok( $m, "authorization_required" );
can_ok( $m, "authorization_required_response" );

my $req = Test::MockObject->new;
my $req_headers = HTTP::Headers->new;

$req->set_always( headers => $req_headers );

my $res = Test::MockObject->new;

my $status;
$res->mock(status => sub { $status = $_[1] });

my $res_headers = HTTP::Headers->new;
$res->set_always( headers => $res_headers );

my $c = Test::MockObject::Extends->new( $m );

my @login_info;
$c->mock( login => sub { shift; @login_info = @_; 1 } );
$c->set_false( "detach" );
$c->set_always( config => {} );
$c->set_always( req => $req );
$c->set_always( res => $res );


ok( !$c->authenticate_http, "http auth fails without header");

$req_headers->authorization_basic( qw/foo bar/ );

ok( $c->authenticate_http, "auth successful with header");
is_deeply( \@login_info, [qw/foo bar/], "login info delegated");

ok( $c->authorization_required, "authorization required with successful authentication");
ok( !$c->called("detach"), "didnt' detach");

$req_headers->clear;
$c->clear;

ok( !$c->authorization_required, "authorization required with bad authentication");
$c->called_ok("detach", "detached");

is( $status, 401, "401 status code" );
like( $res_headers->www_authenticate, qr/^Basic/, "WWW-Authenticate header set");
