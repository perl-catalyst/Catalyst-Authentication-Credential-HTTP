package Catalyst::Plugin::Authentication::Credential::HTTP;
use base qw/Catalyst::Authentication::Credential::HTTP/;

our $VERSION = '0.11';

# FIXME - Add a warning here?
# FIXME - Is this package even needed?

1;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Credential::HTTP - HTTP Basic and Digest authentication
for Catalyst.

=head1 SYNOPSIS

    use Catalyst qw/
        Authentication
        Authentication::Store::Minimal
        Authentication::Credential::HTTP
    /;

=head1 DESCRIPTION

This module is deprecated. Please see L<Catalyst::Authentication::Credential::HTTP>

=head1 AUTHORS

Yuval Kogman, C<nothingmuch@woobling.org>

Jess Robinson

Sascha Kiefer C<esskar@cpan.org>

Tomas Doran C<bobtfish@bobtfish.net>

=head1 SEE ALSO

L<Catalyst::Authentication::Credential::HTTP>.

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005-2006 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut
