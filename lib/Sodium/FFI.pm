package Sodium::FFI;
use strict;
use warnings;

our $VERSION = '0.001';

use Carp qw(croak);
use Data::Dumper::Concise qw(Dumper);
use Exporter qw(import);

use Alien::Sodium;
use FFI::Platypus;
use Path::Tiny qw(path);
use Sub::Util qw(set_subname);

our @EXPORT_OK = qw();

our $ffi;
BEGIN {
    $ffi = FFI::Platypus->new(api => 1, lib => Alien::Sodium->dynamic_libs);
    $ffi->bundle();
}
$ffi->attach('sodium_version_string' => [] => 'string');

# All of these functions don't need to be gated by version.
$ffi->attach('sodium_library_version_major' => [] => 'int');
$ffi->attach('sodium_library_version_minor' => [] => 'int');

our %function = (
    # void
    # sodium_add(unsigned char *a, const unsigned char *b, const size_t len)
    'sodium_add' => [
        ['string', 'string', 'size_t'] => 'void',
        sub {
            my ($xsub, $bin_string1, $bin_string2, $len) = @_;
            return unless $bin_string1 && $bin_string2;
            $len //= length($bin_string1);
            $xsub->($bin_string1, $bin_string2, $len);
        }
    ],

    # char *
    # sodium_bin2hex(char *const hex, const size_t hex_maxlen,
    #   const unsigned char *const bin, const size_t bin_len)
    'sodium_bin2hex' => [
        ['string', 'size_t', 'string', 'size_t'] => 'string',
        sub {
            my ($xsub, $bin_string) = @_;
            return unless $bin_string;
            my $bin_len = length($bin_string);
            my $hex_max = $bin_len * 2;

            my $buffer = "\0" x ($hex_max + 1);
            $xsub->($buffer, $hex_max + 1, $bin_string, $bin_len);
            return substr($buffer, 0, $hex_max);
        }
    ],

    # int
    # sodium_hex2bin(
    #    unsigned char *const bin, const size_t bin_maxlen,
    #    const char *const hex, const size_t hex_len,
    #    const char *const ignore, size_t *const bin_len, const char **const hex_end)
    'sodium_hex2bin' => [
        ['string', 'size_t', 'string', 'size_t', 'string', 'size_t *', 'string *'] => 'int',
        sub {
            my ($xsub, $hex_string, %params) = @_;
            $hex_string //= '';
            my $hex_len = length($hex_string);

            # these two are mostly always void/undef
            my $ignore = $params{ignore};
            my $hex_end = $params{hex_end};

            my $bin_max_len = $params{max_len} // 0;
            if ($bin_max_len <= 0) {
                $bin_max_len = $hex_len;
                $bin_max_len = int($hex_len / 2) unless $ignore;
            }
            my $buffer = "\0" x ($hex_len + 1);
            my $bin_len = 0;

            my $ret = $xsub->($buffer, $hex_len, $hex_string, $hex_len, $ignore, \$bin_len, \$hex_end);
            unless ($ret == 0) {
                croak("sodium_hex2bin failed with: $ret");
            }

            return substr($buffer, 0, $bin_max_len) if $bin_max_len < $bin_len;
            return substr($buffer, 0, $bin_len);
        }
    ],

    # void
    # sodium_increment(unsigned char *n, const size_t nlen)
    'sodium_increment' => [
        ['string', 'size_t'] => 'void',
        sub {
            my ($xsub, $bin_string, $len) = @_;
            return unless $bin_string;
            $len //= length($bin_string);
            $xsub->($bin_string, $len);
        }
    ],

);

our %maybe_function = (
    # int
    # sodium_compare(const unsigned char *b1_,
    #   const unsigned char *b2_, size_t len)
    'sodium_compare' => {
        added => [1,0,4],
        ffi => [
            ['string', 'string', 'size_t'] => 'int',
            sub {
                my ($xsub, $bin_string1, $bin_string2, $len) = @_;
                return unless $bin_string1 && $bin_string2;
                $len //= length($bin_string1);
                my $int = $xsub->($bin_string1, $bin_string2, $len);
                return $int;
            }
        ],
        fallback => sub { croak("sodium_compare not implemented until libsodium v1.0.4"); },
    },

    # int
    # sodium_library_minimal(void)
    'sodium_library_minimal' => {
        added => [1,0,12],
        ffi => [[], 'int'],
        fallback => sub { croak("sodium_library_minimal not implemented until libsodium v1.0.12"); },
    },

    # int
    # sodium_pad(size_t *padded_buflen_p, unsigned char *buf,
    # size_t unpadded_buflen, size_t blocksize, size_t max_buflen)
    'sodium_pad' => {
        added => [1,0,14],
        ffi => [
            ['size_t', 'string', 'size_t', 'size_t', 'size_t'] => 'int',
            sub {
                my ($xsub, $unpadded, $block_size) = @_;
                my $SIZE_MAX = Sodium::FFI::SIZE_MAX;
                my $unpadded_len = length($unpadded);
                $block_size //= 16;
                $block_size = 16 if $block_size < 0;

                my $xpadlen = $block_size - 1;
                if (($block_size & ($block_size - 1)) == 0) {
                    $xpadlen -= $unpadded_len & ($block_size - 1);
                } else {
                    $xpadlen -= $unpadded_len % $block_size;
                }
                if ($SIZE_MAX - $unpadded_len <= $xpadlen) {
                    croak("Input is too large.");
                }

                my $xpadded_len = $unpadded_len + $xpadlen;
                my $padded = "\0" x ($xpadded_len + 1);
                if ($unpadded_len > 0) {
                    my $st = 1;
                    my $i = 0;
                    my $k = $unpadded_len;
                    for my $j (0..$xpadded_len) {
                        substr($padded, $j, 1) = substr($unpadded, $i, 1);
                        $k -= $st;
                        $st = (~((((($k >> 48) | ($k >> 32) | ($k >> 16) | $k) & 0xffff) - 1) >> 16)) & 1;
                        $i += $st;
                    }
                }
                my $int = $xsub->(undef, $padded, $unpadded_len, $block_size, $xpadded_len + 1);
                return $padded;
            }
        ],
        fallback => sub { croak("sodium_pad not implemented until libsodium v1.0.14"); },
    },

    # int
    # sodium_unpad(size_t *unpadded_buflen_p, const unsigned char *buf,
    # size_t padded_buflen, size_t blocksize)
    'sodium_unpad' => {
        added => [1,0,14],
        ffi => [
            ['size_t*', 'string', 'size_t', 'size_t'] => 'int',
            sub {
                my ($xsub, $padded, $block_size) = @_;
                $block_size //= 16;
                $block_size = 16 if $block_size < 0;

                my $SIZE_MAX = Sodium::FFI::SIZE_MAX;
                my $padded_len = length($padded);
                if ($padded_len < $block_size) {
                    croak("Invalid padding.");
                }
                my $unpadded_len = 0;
                my $int = $xsub->(\$unpadded_len, $padded, $padded_len, $block_size);
                return substr($padded, 0, $unpadded_len);
            }
        ],
        fallback => sub { croak("sodium_unpad not implemented until libsodium v1.0.14"); },
    },
);

foreach my $func (keys %function) {
    $ffi->attach($func, @{$function{$func}});
    push(@EXPORT_OK, $func) unless ref($func);
}

foreach my $func (keys %maybe_function) {
    my $href = $maybe_function{$func};
    if (_version_or_better(@{$href->{added}})) {
        $ffi->attach($func, @{$href->{ffi}});
    }
    else {
        # monkey patch in the subref
        no strict 'refs';
        no warnings 'redefine';
        my $pkg = __PACKAGE__;
        *{"${pkg}::$func"} = set_subname("${pkg}::$func", $href->{fallback});
    }
    push @EXPORT_OK, $func;
}

sub _version_or_better {
    my ($maj, $min, $pat) = @_;
    $maj //= 0;
    $min //= 0;
    $pat //= 0;
    foreach my $partial ($maj, $min, $pat) {
        if ($partial =~ /[^0-9]/) {
            croak("_version_or_better requires 1 - 3 integers representing major, minor and patch numbers");
        }
    }
    # if no number was passed in, then the current version is higher
    return 1 unless ($maj || $min || $pat);

    my $version_string = Sodium::FFI::sodium_version_string();
    croak("No version string") unless $version_string;
    my ($smaj, $smin, $spatch) = split(/\./, $version_string);
    return 0 if $smaj < $maj; # full version behind of requested
    return 1 if $smaj > $maj; # full version ahead of requested
    # now we should be matching major versions
    return 1 unless $min; # if we were only given major, move on
    return 0 if $smin < $min; # same major, lower minor
    return 1 if $smaj > $min; # same major, higher minor
    # now we should be matching major and minor, check patch
    return 1 unless $pat; # move on if we were given maj, min only
    return 0 if $spatch < $pat;
    return 1;
}

1;

__END__


=head1 NAME

Sodium::FFI - FFI implementation of libsodium

=head1 SYNOPSIS

  use strict;

=head1 COPYRIGHT

 Copyright 2020 Chase Whitener. All rights reserved.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
