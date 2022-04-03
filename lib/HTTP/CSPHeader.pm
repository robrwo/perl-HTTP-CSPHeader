package HTTP::CSPHeader;

use v5.10;

use Moo;

use Fcntl qw/ O_NONBLOCK O_RDONLY /;
use List::Util 1.29 qw/ pairmap pairs /;
use Math::Random::ISAAC;
use MooX::Const;
use Types::Standard qw/ ArrayRef Bool HashRef Str /;

# RECOMMEND PREREQ: Math::Random::ISAAC::XS
# RECOMMEND PREREQ: Ref::Util::XS

use namespace::autoclean;

has _base_policy => (
    is       => 'const',
    isa      => HashRef,
    required => 1,
    init_arg => 'policy',
);

has _changed => (
    is       => 'rw',
    isa      => Bool,
    lazy     => 1,
    default  => 0,
    init_arg => undef,
);

has nonces_for => (
    is      => 'const',
    isa     => ArrayRef [Str],
    builder => sub { return [] },
);

has nonce => (
    is       => 'lazy',
    isa      => Str,
    clearer  => '_clear_nonce',
    unit_arg => undef,
);

sub _build_nonce {
    my ($self) = @_;

    state $rng = do {
        sysopen( my $fh, '/dev/urandom', O_NONBLOCK | O_RDONLY ) or die $!;
        sysread( $fh, my $data, 16 )                             or die $!;
        close $fh;

        Math::Random::ISAAC->new( unpack( "C*", $data ) );
    };

    return sprintf( '%x', $rng->irand );
}

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

has header => (
    is      => 'lazy',
    isa     => Str,
    clearer => '_clear_header',
);

sub _build_header {
    my ($self) = @_;
    my $policy = $self->policy;
    return join( "; ", pairmap { $a . " " . $b } %$policy );
}

sub reset {
    my ($self) = @_;
    return unless $self->_changed;
    $self->_clear_nonce;
    $self->_clear_policy;
    $self->_clear_header;
    $self->_changed(0);
}

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
