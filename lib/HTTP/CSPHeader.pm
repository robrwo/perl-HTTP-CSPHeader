package HTTP::CSPHeader;

# ABSTRACT: manage dynamic content security policy headers

use v5.14;

use Moo;

use Crypt::URandom 0.37 qw/ urandom_ub /;
use Fcntl qw/ O_NONBLOCK O_RDONLY /;
use List::Util 1.29 qw/ pairmap pairs /;
use Math::Random::ISAAC;
use Types::Common 2.000000 qw/ ArrayRef is_ArrayRef Bool HashRef IntRange Str /;

# RECOMMEND PREREQ: Math::Random::ISAAC::XS
# RECOMMEND PREREQ: Ref::Util::XS
# RECOMMEND PREREQ: Type::Tiny::XS

use namespace::autoclean;

our $VERSION = 'v0.3.1';

=head1 SYNOPSIS

  use HTTP::CSPheader;

  my $csp = HTTP::CSPheader->new(
    policy => {
       "default-src" => q['self'],
       "script-src"  => q['self' cdn.example.com],
    },
    nonces_for => [qw/ script-src /],
  );

  ...

  use HTTP::Headers;

  my $h = HTTP::Headers->new;

  $csp->reset;

  $h->amend(
    "+script-src" => "https://captcha.example.com",
    "+style-src"  => "https://captcha.example.com",
  );

  my $nonce = $csp->nonce;
  $h->header( 'Content-Security-Policy' => $csp->header );

  my $body = ...

  $body .= "<script nonce="${nonce}"> ... </script>";

=head1 DESCRIPTION

This module allows you to manage Content-Security-Policy (CSP) headers.

It supports dynamic changes to headers, for example, adding a source
for a specific page, or managing a random nonce for inline scripts or
styles.

It also supports caching, so that the header will only be regenerated
if there is a change.

=attr policy

This is a hash reference of policies.  The keys a directives, and the
values are sources.

There is no validation of these values.

=cut

has _base_policy => (
    is       => 'ro',
    isa      => HashRef,
    required => 1,
    init_arg => 'policy',
);

has policy => (
    is       => 'lazy',
    isa      => HashRef,
    clearer  => '_clear_policy',
    init_arg => undef,
);

sub _build_policy {
    my ($self) = @_;
    my %policy = %{ $self->_base_policy };
    if ( my @dirs = @{ $self->nonces_for } ) {
        my $nonce = "'nonce-" . $self->nonce . "'";
        for my $dir (@dirs) {
            if ( defined $policy{$dir} ) {
                $policy{$dir} .= " " . $nonce;
            }
            else {
                $policy{$dir} = $nonce;
            }
        }
        $self->_changed(1);
    }
    return \%policy;
}

has _changed => (
    is       => 'rw',
    isa      => Bool,
    lazy     => 1,
    default  => 0,
    init_arg => undef,
);

=attr nonces_for

This is an array reference of the directives to add a random L</nonce>
to when the L</policy> is regenerated.

Note that the same nonce will be added to all of the directives, since
using separate nonces does not improve security.

It is emply by default.

A single value will be coerced to an array.

This does not validate the values.

Note that if a directive allows C<'unsafe-inline'> then a nonce may
cancel out that value.

=cut

has nonces_for => (
    is      => 'lazy',
    isa     => ArrayRef [Str],
    builder => sub { return [] },
    coerce  => sub { my $val = is_ArrayRef( $_[0] ) ? $_[0] : [ $_[0] ] },
);

=attr nonce_seed_size

This is the size of the random seed data for the L</nonce>. It can be an integer between 16 and 256.

=cut

has nonce_seed_size => (
    is      => 'lazy',
    isa     => IntRange[ 16, 256 ],
    default => 16,
);

=attr nonce

This is the random nonce that is added to directives in L</nonces_for>.

The nonce is a hex string based on a random 32-bit number, which is generated
from L<Math::Random::ISAAC>.  The RNG is seeded by L<Crypt::URandom>.

If you want to change how it is generated, you can override the C<_build_nonce>
method in a subclass.

Note that you should never make an assumption about the format of the
nonce, as the source may change in future versions.

=cut

has nonce => (
    is       => 'lazy',
    isa      => Str,
    clearer  => '_clear_nonce',
    unit_arg => undef,
);

sub _build_nonce {
    my ($self) = @_;

    state $rng = do {
        my $data = urandom_ub( $self->nonce_seed_size );
        Math::Random::ISAAC->new( unpack( "C*", $data ) );
    };

    return sprintf( '%x', $rng->irand ^ $$ );
}

=attr header

This is the value of the header, generated from the L</policy>.

This is a read-only accessor.

=cut

has header => (
    is       => 'lazy',
    isa      => Str,
    clearer  => '_clear_header',
    init_arg => undef,
);

sub _build_header {
    my ($self) = @_;
    my $policy = $self->policy;
    return join( "; ", pairmap { $a . " " . $b } %$policy );
}

=method reset

This resets any changes to the L</policy> and clears the L</nonce>.
It should be run at the start of each HTTP request.

If you never make use of the nonce, and never L</amend> the headers,
then you do not need to run this method.

=cut

sub reset {
    my ($self) = @_;
    return unless $self->_changed;
    $self->_clear_nonce;
    $self->_clear_policy;
    $self->_clear_header;
    $self->_changed(0);
}

=method amend

  $csp->amend( $directive1 => $value1, $directive2 => $value2, ... );

This amends the L</policy>.

If the C<$directive> starts with a C<+> then the value will be
appended to it.  Otherwise the change will overwrite the value.

If the value is C<undef>, then the directive will be deleted.

=cut

sub amend {
    my ($self, @args) = @_;
    my $policy = $self->policy;

    if (@args) {

        for my $pol ( pairs @args ) {

            my ( $dir, $val ) = @$pol;

            if ( $dir =~ s/^\+// ) {    # append to directive
                if ( exists $policy->{$dir} ) {
                    $policy->{$dir} .= " " . $val;
                }
                elsif ( defined $val ) {
                    $policy->{$dir} = $val;
                }

            }
            else {
                if ( defined $val ) {
                    $policy->{$dir} = $val;
                }
                else {
                    delete $policy->{$dir};
                }
            }
        }

        $self->_clear_header;
        $self->_changed(1);
    }

    return $policy;
}

1;

=head1 EXAMPLES

=head2 Mojolicious

You can use this with L<Mojolicious>:

  use HTTP::CSPHeader;

  use feature 'state';

  $self->hook(
    before_dispatch => sub ($c) {

      state $csp = HTTP::CSPHeader->new(
          policy => {
              'default-src' => q['self'],
              'script-src'  => q['self'],
          },
          nonces_for => 'script-src',
      );

      $csp->reset;

      $c->stash( csp_nonce => $csp->nonce );

      $c->res->headers->content_security_policy( $csp->header );
    }
  );

and in your templates, you can use the following for inline scripts:

  <script nonce="<%= $csp_nonce %>"> ... </script>

If you do not need the nonce, then you might consider using L<Mojolicious::Plugin::CSPHeader>.

=head1 SUPPORT FOR OLDER PERL VERSIONS

Since v0.2.0, the this module requires Perl v5.14 or later.

If you need this module on Perl v5.10, please use one of the v0.1.x
versions of this module.  Significant bug or security fixes may be
backported to those versions.

=head1 SEE ALSO

L<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy>

L<HTTP::SecureHeaders>

L<Plack::Middleware::CSP>

=cut
