#!/usr/bin/perl

# License:		GPLv3 - see license file or http://www.gnu.org/licenses/gpl.html
# Program-version:	1.0, (16th March 2019)
# Description:		Find passwords of yours in the pawned database
# Contact:		Dominik Bernhardt - domasprogrammer@gmail.com or https://github.com/DomAsProgrammer (program only, not database)

# License
#    Copyright (C) 2019  Dominik Bernhardt

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;
use Digest::SHA qw(sha1_hex);
use Term::ANSIColor;

my $show	= 0;
if ( grep(/^--show-passwords?$/, @ARGV) ) {
	$show	= 1;
	@ARGV	= grep(!/^--show-passwords?$/, @ARGV);
	}
my $file	= shift(@ARGV);
my @passwords	= ();
my $lines	= 0;
my @matches	= ();

$SIG{INT}	= sub {
	&clear_and_reset(128);
	};

if ( !defined($file) || ( defined($file) && ( ! -s $file || ! -T $file ) ) ) {
	print STDERR color("red") . "Missing text file with sha1 codes!\n\n" . color("reset");
	exit(1);
	}

print "\n\n    pwned-checker.pl - check database of https://haveibeenpwned.com/Passwords
    Copyright (C) 2019  Dominik Bernhardt

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.\n\n";

print "You can quit everytime by pressing [Ctrl] + [C]\n";

Passwords:
while ( 1 ) {
	print "\nWhat to do now?\n\n",
		"\ta: Add a password\n",
		"\tr: Run check\n",
		"\nAnswer: ";
	chomp(my $answer = <STDIN>);

	if ( $answer =~ m/^a(?:dd)?$/i ) {
		print "\nPassword to add: ";
		my $pw1		= "";
		my $pw2		= "";
		if ( !$show ) {
			system("stty -echo");
			}
		chomp($pw1	= <STDIN>);
		$pw1		= sha1_hex($pw1);

		if ( !$show ) {
			print "\nRepeat password: ";
			chomp($pw2	= <STDIN>);
			$pw2		= sha1_hex($pw2);
			}

		system("stty echo");

		if ( !$show && $pw1 ne $pw2 ) {
			print STDERR color("red") . "\nPasswords don't match!\nNothing added.\n" . color("reset");
			}
		else {
			push(@passwords, $pw1);
			print color("green") , ( !$show ) ? "\n" : "", "Added as \"$pw1\".\n" . color("reset");

			# Overwrite
			$pw1	= "pw1 was added to array.";
			$pw1	= sha1_hex($pw1);
			$pw2	= "pw2 was just overwritten.";
			$pw2	= sha1_hex($pw2);
			}
		}
	elsif ( $answer =~ m/^r(?:un)?$/i ) {
		if ( @passwords ) {
			last(Passwords);
			}
		else {
			print STDERR color("red") . "No passwords given; end...\n\n" . color("reset");
			exit(0);
			}
		}
	else {
		print STDERR "No idea what you mean by \"$answer\"! XD\n\n";
		$answer	= sha1_hex($answer);
		$answer	= "Overwrite in case of entering a password by accident.";
		$answer	= sha1_hex($answer);
		}
	}


open(FH, "<", $file) or die "Can't read file \"$file\"\n";
	while ( my $line = <FH> ) {
		print "Line: " . sprintf("% 11s", &readable(++$lines)) . "\r";

		if ( $line =~ m/^(.+):([0-9]*)/i ) {
			my $sha1	= $1;
			my $uses	= $2;

			if ( grep(/^$sha1$/i, @passwords) ) {
				push(@matches, $sha1);
				print color("red") . "Line: " . sprintf("% 11s", &readable($lines)) . " - Password found! (" . &readable($uses) . " times used)\n" . color("reset");

				if ( scalar(@matches) >= scalar(@passwords) ) {
					print STDERR color("red") . "All given passwords are broken; stop testing...\n\n" . color("reset");
					last;
					}
				}
			}
		}
close(FH);

my $txt		= "\n" . scalar(@matches) . " of " . scalar(@passwords) . " where pwned.\n\n";
if ( @matches ) {
	print STDERR color("red") . $txt . color("reset");
	foreach my $match ( @matches ) {
		print "\t$match\n";
		}
	print "\n";
	&clear_and_reset(0);
	}
else {
	print STDERR color("green") . $txt . color("reset") . "Good job! =)\n\n";
	&clear_and_reset(0);
	}

sub readable {
	my $num	= shift;
	$num	= reverse(join(",", unpack("(A3)*", reverse($num))));
	return($num);
	}

sub clear_and_reset {
	my $exit	= shift;

	if ( $exit ) {
	print STDERR "\nInterrupted by user\n";
		}

	system("stty echo");
	foreach my $pw ( @passwords ) {
		$pw	= "anything to overwrite here!";
		$pw	= sha1_hex($pw);
		}

	exit($exit);
	}
