#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Credential::HTTP;
use base qw/Catalyst::Plugin::Authentication::Credential::Password/;

use strict;
use warnings;

use String::Escape ();
use URI::Escape    ();
use Catalyst       ();
use Digest::MD5    ();

our $VERSION = "0.07";

sub authenticate_http {
    my ( $c, @args ) = @_;

    return 1 if $c->_is_http_auth_type('digest') && $c->authenticate_digest(@args);
    return 1 if $c->_is_http_auth_type('basic')  && $c->authenticate_basic(@args);
}

sub get_http_auth_store {
    my ( $c, %opts ) = @_;

    my $store = $opts{store} || $c->config->{authentication}{http}{store} || return;

    return ref $store
        ? $store
        : $c->get_auth_store($store);
}

sub authenticate_basic {
    my ( $c, %opts ) = @_;

    $c->log->debug('Checking http basic authentication.') if $c->debug;

    my $headers = $c->req->headers;

    if ( my ( $username, $password ) = $headers->authorization_basic ) {

        my $user;

        unless ( $user = $opts{user} ) {
            if ( my $store = $c->get_http_auth_store(%opts) ) {
                $user = $store->get_user($username);
            } else {
                $user = $username;
            }
        }

        return $c->login( $user, $password );
    }

    return 0;
}

sub authenticate_digest {
    my ( $c, %opts ) = @_;

    $c->log->debug('Checking http digest authentication.') if $c->debug;

    my $headers       = $c->req->headers;
    my @authorization = $headers->header('Authorization');
    foreach my $authorization (@authorization) {
        next unless $authorization =~ m{^Digest};

        my %res = map {
            my @key_val = split /=/, $_, 2;
            $key_val[0] = lc $key_val[0];
            $key_val[1] =~ s{"}{}g;    # remove the quotes
            @key_val;
        } split /,\s?/, substr( $authorization, 7 );    #7 == length "Digest "

        my $opaque = $res{opaque};
        my $nonce  = $c->get_digest_authorization_nonce( __PACKAGE__ . '::opaque:' . $opaque );
        next unless $nonce;

        $c->log->debug('Checking authentication parameters.')
          if $c->debug;

        my $uri         = '/' . $c->request->path;
        my $algorithm   = $res{algorithm} || 'MD5';
        my $nonce_count = '0x' . $res{nc};

        my $check = $uri eq $res{uri}
          && ( exists $res{username} )
          && ( exists $res{qop} )
          && ( exists $res{cnonce} )
          && ( exists $res{nc} )
          && $algorithm eq $nonce->algorithm
          && hex($nonce_count) > hex( $nonce->nonce_count )
          && $res{nonce} eq $nonce->nonce;    # TODO: set Stale instead

        unless ($check) {
            $c->log->debug('Digest authentication failed. Bad request.')
              if $c->debug;
            $c->res->status(400);             # bad request
            die $Catalyst::DETACH;
        }

        $c->log->debug('Checking authentication response.')
          if $c->debug;

        my $username = $res{username};
        my $realm    = $res{realm};

        my $user;

        unless ( $user = $opts{user} ) {
            if ( my $store = $c->get_http_auth_store(%opts) || $c->default_auth_store ) {
                $user = $store->get_user($username);
            }
        }

        unless ($user) {    # no user, no authentication
            $c->log->debug('Unknown user: $user.') if $c->debug;
            return 0;
        }

        # everything looks good, let's check the response

        # calculate H(A2) as per spec
        my $ctx = Digest::MD5->new;
        $ctx->add( join( ':', $c->request->method, $res{uri} ) );
        if ( $res{qop} eq 'auth-int' ) {
            my $digest =
              Digest::MD5::md5_hex( $c->request->body );    # not sure here
            $ctx->add( ':', $digest );
        }
        my $A2_digest = $ctx->hexdigest;

        # the idea of the for loop:
        # if we do not want to store the plain password in our user store,
        # we can store md5_hex("$username:$realm:$password") instead
        for my $r ( 0 .. 1 ) {

            # calculate H(A1) as per spec
            my $A1_digest = $r ? $user->password : do {
                $ctx = Digest::MD5->new;
                $ctx->add( join( ':', $username, $realm, $user->password ) );
                $ctx->hexdigest;
            };
            if ( $nonce->algorithm eq 'MD5-sess' ) {
                $ctx = Digest::MD5->new;
                $ctx->add( join( ':', $A1_digest, $res{nonce}, $res{cnonce} ) );
                $A1_digest = $ctx->hexdigest;
            }

            my $rq_digest = Digest::MD5::md5_hex(
                join( ':',
                    $A1_digest, $res{nonce},
                    $res{qop} ? ( $res{nc}, $res{cnonce}, $res{qop} ) : (),
                    $A2_digest )
            );

            $nonce->nonce_count($nonce_count);
            $c->cache->set( __PACKAGE__ . '::opaque:' . $nonce->opaque,
                $nonce );

            return $c->login( $user, $user->password )
              if $rq_digest eq $res{response};
        }
    }

    return 0;
}

sub _check_cache {
    my $c = shift;

    die "A cache is needed for http digest authentication."
      unless $c->can('cache');
}

sub _is_http_auth_type {
    my ( $c, $type ) = @_;

    my $cfgtype = lc( $c->config->{authentication}{http}{type} || 'any' );
    return 1 if $cfgtype eq 'any' || $cfgtype eq lc $type;
    return 0;
}

sub authorization_required {
    my ( $c, @args ) = @_;

    return 1 if $c->authenticate_http(@args);
    
    $c->authorization_required_response(@args);

    die $Catalyst::DETACH;
}

sub authorization_required_response {
    my ( $c, %opts ) = @_;

    $c->res->status(401);

    # *DONT* short circuit
    my $ok;
    $ok++ if $c->_create_digest_auth_response(\%opts);
    $ok++ if $c->_create_basic_auth_response(\%opts);

    unless ( $ok ) {
        die 'Could not build authorization required response. '
        . 'Did you configure a valid authentication http type: '
        . 'basic, digest, any';
    }
}

sub _add_authentication_header {
    my ( $c, $header ) = @_;
    $c->res->headers->push_header( 'WWW-Authenticate' => $header );
}

sub _create_digest_auth_response {
    my ( $c, $opts ) = @_;
      
    return unless $c->_is_http_auth_type('digest');
    
    if ( my $digest = $c->_build_digest_auth_header( $opts ) ) {
        $c->_add_authentication_header( $digest );
        return 1;
    }

    return;
}

sub _create_basic_auth_response {
    my ( $c, $opts ) = @_;
    
    return unless $c->_is_http_auth_type('basic');

    if ( my $basic = $c->_build_basic_auth_header( $opts ) ) {
        $c->_add_authentication_header( $basic );
        return 1;
    }

    return;
}

sub _build_auth_header_realm {
    my ( $c, $opts ) = @_;    

    if ( my $realm = $opts->{realm} ) {
        return 'realm=' . String::Escape::qprintable($realm);
    } else {
        return;
    }
}

sub _build_auth_header_domain {
    my ( $c, $opts ) = @_;

    if ( my $domain = $opts->{domain} ) {
        Catalyst::Exception->throw("domain must be an array reference")
          unless ref($domain) && ref($domain) eq "ARRAY";

        my @uris =
          $c->config->{authentication}{http}{use_uri_for}
          ? ( map { $c->uri_for($_) } @$domain )
          : ( map { URI::Escape::uri_escape($_) } @$domain );

        return qq{domain="@uris"};
    } else {
        return;
    }
}

sub _build_auth_header_common {
    my ( $c, $opts ) = @_;

    return (
        $c->_build_auth_header_realm($opts),
        $c->_build_auth_header_domain($opts),
    );
}

sub _build_basic_auth_header {
    my ( $c, $opts ) = @_;
    return $c->_join_auth_header_parts( Basic => $c->_build_auth_header_common( $opts ) );
}

sub _build_digest_auth_header {
    my ( $c, $opts ) = @_;

    my $nonce = $c->_digest_auth_nonce($opts);

    my $key = __PACKAGE__ . '::opaque:' . $nonce->opaque;
   
    $c->store_digest_authorization_nonce( $key, $nonce );

    return $c->_join_auth_header_parts( Digest =>
        $c->_build_auth_header_common($opts),
        map { sprintf '%s="%s"', $_, $nonce->$_ } qw(
            qop
            nonce
            opaque
            algorithm
        ),
    );
}

sub _digest_auth_nonce {
    my ( $c, $opts ) = @_;

    my $package = __PACKAGE__ . '::Nonce';

    my $nonce   = $package->new;

    if ( my $algorithm = $opts->{algorithm} || $c->config->{authentication}{http}{algorithm}) { 
        $nonce->algorithm( $algorithm );
    }

    return $nonce;
}

sub _join_auth_header_parts {
    my ( $c, $type, @parts ) = @_;
    return "$type " . join(", ", @parts );
}

sub get_digest_authorization_nonce {
    my ( $c, $key ) = @_;

    $c->_check_cache;
    $c->cache->get( $key );
}

sub store_digest_authorization_nonce {
    my ( $c, $key, $nonce ) = @_;

    $c->_check_cache;
    $c->cache->set( $key, $nonce );
}

package Catalyst::Plugin::Authentication::Credential::HTTP::Nonce;

use strict;
use base qw[ Class::Accessor::Fast ];
use Data::UUID ();

our $VERSION = "0.01";

__PACKAGE__->mk_accessors(qw[ nonce nonce_count qop opaque algorithm ]);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new(@_);

    $self->nonce( Data::UUID->new->create_b64 );
    $self->opaque( Data::UUID->new->create_b64 );
    $self->qop('auth,auth-int');
    $self->nonce_count('0x0');
    $self->algorithm('MD5');

    return $self;
}

1;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Credential::HTTP - HTTP Basic and Digest authentication
for Catlayst.

=head1 SYNOPSIS

    use Catalyst qw/
        Authentication
        Authentication::Store::Moose
        Authentication::Credential::HTTP
    /;

    __PACKAGE__->config->{authentication}{http}{type} = 'any'; # or 'digest' or 'basic'
    __PACKAGE__->config->{authentication}{users} = {
        Mufasa => { password => "Circle Of Life", },
    };

    sub foo : Local {
        my ( $self, $c ) = @_;

        $c->authorization_required( realm => "foo" ); # named after the status code ;-)

        # either user gets authenticated or 401 is sent

        do_stuff();
    }

    # with ACL plugin
    __PACKAGE__->deny_access_unless("/path", sub { $_[0]->authenticate_http });

    sub end : Private {
        my ( $self, $c ) = @_;

        $c->authorization_required_response( realm => "foo" );
        $c->error(0);
    }

=head1 DESCRIPTION

This moduule lets you use HTTP authentication with
L<Catalyst::Plugin::Authentication>. Both basic and digest authentication
are currently supported.

=head1 METHODS

=over 4

=item authorization_required %opts

Tries to C<authenticate_http>, and if that fails calls
C<authorization_required_response> and detaches the current action call stack.

This method just passes the options through untouched.

=item authenticate_http %opts

Looks inside C<< $c->request->headers >> and processes the digest and basic
(badly named) authorization header.

This will only try the methods set in the configuration.

See the next two methods for what %opts can contain.

=item authenticate_basic %opts

=item authenticate_digest %opts

Try to authenticate one of the methods without checking if the method is
allowed in the configuration.

%opts can contain C<store> (either an object or a name), C<user> (to disregard
%the username from the header altogether, overriding it with a username or user
%object).

=item authorization_required_response %opts

Sets C<< $c->response >> to the correct status code, and adds the correct
header to demand authentication data from the user agent.

Typically used by C<authorization_required>, but may be invoked manually.

%opts can contain C<realm>, C<domain> and C<algorithm>, which are used to build
%the digest header.

=item store_digest_authorization_nonce $key, $nonce

=item get_digest_authorization_nonce $key

Set or get the C<$nonce> object used by the digest auth mode.

You may override these methods. By default they will call C<get> and C<set> on
C<< $c->cache >>.

=back

=head1 CONFIGURATION

All configuration is stored in C<< YourApp->config->{authentication}{http} >>.

This should be a hash, and it can contain the following entries:

=over 4

=item store

Either a name or an object -- the default store to use for HTTP authentication.

=item type

Can be either C<any> (the default), C<basic> or C<digest>.

This controls C<authorization_required_response> and C<authenticate_http>, but
not the "manual" methods.

=back

=head1 AUTHORS

Yuval Kogman, C<nothingmuch@woobling.org>

Jess Robinson

Sascha Kiefer C<esskar@cpan.org>

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005-2006 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut
