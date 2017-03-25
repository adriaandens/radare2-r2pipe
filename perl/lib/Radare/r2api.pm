# Declare namespace
package Radare::r2api;

# Declare dependencies
use strict;
use warnings;

# Use r2pipe in the background
use Radare::r2pipe;

# JSON support
use JSON;

use Data::Printer;

# Version
our $VERSION = 0.2;

# Autoload
our $AUTOLOAD;

sub new {
    my $class = shift;
    my $self = {};

    # Bless you.
    bless $self, $class;

    # Initialize r2pipe
    $self->init_r2pipe(shift) if @_;

    # Initialize functions
    $self->{functions} = decode_json('{"disassembleFunction":{"r2_args":[[],["addr"]],"r2_cmd":"pdfj"},"info":{"r2_cmd":"iIj","r2_args":[]},"stripped":{"r2_cmd":"iI~stripped[1]"},"getFunctions":{"r2_cmd":"aflj","r2_args":[]},"analyze":{"r2_cmd":"aa","r2_args":[]},"seek":{"r2_cmd":"s","r2_args":[[],["arg"]]}}');

    return $self;
}

sub init_r2pipe {
    my ($self, $r2pipe_arg) = @_;
    $self->{r2pipe} = Radare::r2pipe->new($r2pipe_arg);
}

sub AUTOLOAD {
    my ($self, @arguments) = @_;

    # Get function name that was requested
    my ($function_name) = ($AUTOLOAD =~ /Radare::r2api::(.+)/);
    print "Debug: '$function_name' was requested\n";

    # Check if this function exists
    if(defined $self->{functions}->{$function_name}) {
        print "Debug: function '$function_name' exists!\n";
    } else {
        die "Bluh: function does not exist.\n";
    }
   
    # Get the correct argument mapping for the number of arguments
    my $number_of_parameters = scalar(@arguments);
    print "Debug: $number_of_parameters parameters were passed to this function.\n";
    my %zip_it;
    if($number_of_parameters > 0 && defined $self->{functions}->{$function_name}->{r2_args}) {
        print "First check OK\n";
        my @r2_args = @{$self->{functions}->{$function_name}->{r2_args}};
        p @r2_args;
        if(scalar(@r2_args) <= $number_of_parameters) {
            die "Bluh: we don't support that amount of parameters\n";
        }
        my @meaning_of_parameters = @{$r2_args[$number_of_parameters]};
        %zip_it = (); my $i = 0;
        foreach(@meaning_of_parameters) {
            $zip_it{$_} = $arguments[$i++];        
        }
    } elsif($number_of_parameters == 0) {
        print "Debug: no parameters! All OK.\n";
    }

    # Create the r2 command
    my $cmd = '';
    $cmd .= $zip_it{times} if defined $zip_it{times};
    $cmd .= $self->{functions}->{$function_name}->{r2_cmd};
    $cmd .= ' ' . $zip_it{arg} if defined $zip_it{arg};
    $cmd .= '~' . $zip_it{grep} if defined $zip_it{grep};
    $cmd .= '@' . $zip_it{addr} if defined $zip_it{addr};
    $cmd .= '!' . $zip_it{size} if defined $zip_it{size};

    print "Debug: r2 command = '$cmd'\n";

    return $self->{r2pipe}->cmdj($cmd);
}

sub DESTROY {}

1;
