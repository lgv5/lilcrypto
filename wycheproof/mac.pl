#!/usr/bin/env perl
use v5.38;;
use strict;
use warnings;

use Getopt::Std;
use JSON::PP;

my $progname = $0 =~ s@.*/@@r;

sub slurp ($fh) { local $/; <$fh> }

sub usage ()
{
	say STDERR "Usage: $progname [-Cv] -x runner json_file ",
	    "[json_files ...]";
	exit 1;
}

sub main ()
{
	my %opts;
	my $rc = 0;

	getopts("Cvx:", \%opts) && @ARGV > 0 or usage;
	usage unless defined $opts{"x"};

	for my $f (@ARGV) {
		open(my $fh, "<", $f) or die "open failed: $!";

		my $json = decode_json(slurp($fh));
		for my $testgroup ($json->{testGroups}->@*) {
			for my $test ($testgroup->{tests}->@*) {
				my @args;

				push(@args, $json->{algorithm});
				push(@args, "-K", $testgroup->{keySize});
				push(@args, "-k", $test->{key});
				push(@args, "-m", $test->{msg});
				push(@args, "-T", $testgroup->{tagSize});
				push(@args, "-t", $test->{tag});
				push(@args, "-v") if $opts{"v"};

				open(my $th, "-|", $opts{"x"}, @args) or die;
				my $result = slurp($th);
				close($th);

				chomp($result);
				if ($result ne $test->{result}) {
					$rc = 1;
					say STDERR "case $test->{tcId}: ",
					    "expected $test->{result}: ",
					    "$test->{comment} [",
					    join(",", $test->{flags}->@*),
					    "]";
					exit 1 unless $opts{"C"};
				}
			}
		}

		close($fh);
	}

	say "ALL TESTS PASSED!" if $rc == 0;
	return $rc;
}

exit main;
