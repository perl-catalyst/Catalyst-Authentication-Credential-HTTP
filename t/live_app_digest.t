#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
BEGIN {
    eval { require Test::WWW::Mechanize::Catalyst }
      or plan skip_all =>
      "Test::WWW::Mechanize::Catalyst is needed for this test";
    eval { require Catalyst::Plugin::Cache }
      or plan skip_all =>
      "Catalyst::Plugin::Cache is needed for this test";
    eval { require Cache::FileCache }
      or plan skip_all =>
      "Cache::FileCache is needed for this test";
    plan tests => 12;
}
use Digest::MD5;
use HTTP::Request;
{
    package AuthTestApp;
    use Catalyst qw/
      Authentication
      Cache
      /;
    use Test::More;
    our %users;
    sub moose : Local {
        my ( $self, $c ) = @_;
        #$c->authenticate( { realm => 'testrealm@host.com' } );
        $c->authenticate();
        $c->res->body( $c->user->id );
    }
    my $digest_pass = Digest::MD5->new;
    $digest_pass->add('Mufasa2:testrealm@host.com:Circle Of Life');
    %users = ( 
        Mufasa  => { pass         => "Circle Of Life",          }, 
        Mufasa2 => { pass         => $digest_pass->hexdigest, },
    );
    __PACKAGE__->config->{cache}{backend} = {
        class => 'Cache::FileCache',
    };
    __PACKAGE__->config( authentication => {
        default_realm => 'testrealm@host.com',
        realms => {
            'testrealm@host.com' => {
                store => {
                    class => 'Minimal',
                    users => \%users,
                },
                credential => {
                    class => 'HTTP',
                    type  => 'digest',
                    password_type => 'clear', 
                    password_field => 'pass'
                },
            },
        },
    });
    __PACKAGE__->setup;
}
use Test::WWW::Mechanize::Catalyst qw/AuthTestApp/;

sub do_test {
    my $username = shift;
    my $uri = shift;
    my $mech = Test::WWW::Mechanize::Catalyst->new;
    $mech->get("http://localhost/moose");
    is( $mech->status, 401, "status is 401" );
    my $www_auth = $mech->res->headers->header('WWW-Authenticate');
    my %www_auth_params = map {
        my @key_val = split /=/, $_, 2;
        $key_val[0] = lc $key_val[0];
        $key_val[1] =~ s{"}{}g;    # remove the quotes
        @key_val;
    } split /, /, substr( $www_auth, 7 );    #7 == length "Digest "
    $mech->content_lacks( "foo", "no output" );
    my $response = '';
    {
        my $password = 'Circle Of Life';
        my $realm    = $www_auth_params{realm};
        my $nonce    = $www_auth_params{nonce};
        my $cnonce   = '0a4f113b';
        my $opaque   = $www_auth_params{opaque};
        my $nc       = '00000001';
        my $method   = 'GET';
        my $qop      = 'auth';
        $uri         ||= '/moose';
        my $ctx = Digest::MD5->new;
        $ctx->add( join( ':', $username, $realm, $password ) );
        my $A1_digest = $ctx->hexdigest;
        $ctx = Digest::MD5->new;
        $ctx->add( join( ':', $method, $uri ) );
        my $A2_digest = $ctx->hexdigest;
        my $digest = Digest::MD5::md5_hex(
            join( ':',
                $A1_digest, $nonce, $qop ? ( $nc, $cnonce, $qop ) : (), $A2_digest )
        );

        $response = qq{Digest username="$username", realm="$realm", nonce="$nonce", uri="$uri", qop=$qop, nc=$nc, cnonce="$cnonce", response="$digest", opaque="$opaque"};
    }
    my $r = HTTP::Request->new( GET => "http://localhost" . $uri );
    $mech->request($r);
    $r->headers->push_header( Authorization => $response );
    $mech->request($r);
    is( $mech->status, 200, "status is 200" );
    $mech->content_contains( $username, "Mufasa output" );
}

do_test('Mufasa');
do_test('Mufasa2');
do_test('Mufasa', '/moose?moose_id=1'); # Digest auth includes the full URL path, so need to test query strings
