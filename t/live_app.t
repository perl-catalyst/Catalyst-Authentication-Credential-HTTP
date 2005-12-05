#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;
use HTTP::Request;

{
	package AuthTestApp;
	use Catalyst qw/
		Authentication
		Authentication::Store::Minimal
		Authentication::Credential::HTTP
	/;

	use Test::More;
	use Test::Exception;

	use Digest::MD5 qw/md5/;

	our $users;

	sub moose : Local {
		my ( $self, $c ) = @_;

        $c->authorization_required;

        $c->res->body("foo");
	}

	__PACKAGE__->config->{authentication}{users} = $users = {
		foo => {
			password => "s3cr3t",
		},
		bar => {
			crypted_password => crypt("s3cr3t", "x8"),
		},
		gorch => {
			hashed_password => md5("s3cr3t"),
			hash_algorithm => "MD5",
		},
		baz => {},
	};

	__PACKAGE__->setup;
}

use Test::WWW::Mechanize::Catalyst qw/AuthTestApp/;

my $mech = Test::WWW::Mechanize::Catalyst->new;

$mech->get("http://localhost/moose");
is( $mech->status, 401, "status is 401");

$mech->content_lacks("foo", "no output");

my $r = HTTP::Request->new( GET => "http://localhost/moose" );
$r->authorization_basic(qw/foo s3cr3t/);

$mech->request( $r );
is( $mech->status, 200, "status is 200");
$mech->content_contains("foo", "foo output");


