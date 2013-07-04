package Passwd::Keyring::OSXKeychain;

use warnings;
use strict;

use Carp qw(croak);
use IPC::System::Simple qw(capturex systemx);

=head1 NAME

Passwd::Keyring::OSXKeychain - Password storage implementation based on OSX/Keychain.

=head1 VERSION

Version 0.1004

=cut

our $VERSION = '0.1004';

=head1 WARNING

I do not have Mac. I wrote the library mimicking actions
of some python libraries and tested using mocks, but help
of somebody able to test it on true Mac is really needed.

=head1 SYNOPSIS

OSXKeychain Keyring based implementation of L<Keyring>. Provide secure
storage for passwords and similar sensitive data.

    use Passwd::Keyring::OSXKeychain;

    my $keyring = Passwd::Keyring::OSXKeychain->new(
         app=>"blahblah scraper",
         group=>"Johnny web scrapers",
    );

    my $username = "John";  # or get from .ini, or from .argv...

    my $password = $keyring->get_password($username, "blahblah.com");
    unless( $password ) {
        $password = <somehow interactively prompt for password>;

        # securely save password for future use
        $keyring->set_password($username, $password, "blahblah.com");
    }

    login_somewhere_using($username, $password);
    if( password_was_wrong ) {
        $keyring->clear_password($username, "blahblah.com");
    }

Note: see L<Passwd::Keyring::Auto::KeyringAPI> for detailed comments
on keyring method semantics (this document is installed with
C<Passwd::Keyring::Auto> package).

=head1 SUBROUTINES/METHODS

=head2 new(app=>'app name', group=>'passwords folder')

Initializes the processing. Croaks if osxkeychain keyring does not 
seem to be available.

Handled named parameters: 

- app - symbolic application name (not used at the moment, but can be
  used in future as comment and in prompts, so set sensibly)

- group - name for the password group (will be visible in seahorse so
  can be used by end user to manage passwords, different group means
  different password set, a few apps may share the same group if they
  need to use the same passwords set)

(OSXKeychain-specific)

- security_prog - location of security program (/usr/bin/security by
  default, possibility to overwrite is mostly needed for testing)

- keychain - keychain to use (if not default)

=cut

sub new {
    my ($cls, %opts) = @_;
    my $self = {
        app => $opts{app} || 'Passwd::Keyring',
        group => $opts{group} || 'Passwd::Keyring unclassified passwords',
        security => $opts{security_prog} || '/usr/bin/security',
        keychain => $opts{keychain},
    };
    bless $self;

    unless( -x $self->{security} ) {
        croak("OSXKeychain not available: security program $self->{security} is missing");
    }
    if($self->{keychain}) {
        # Add .keychain suffix if missing
        $self->{keychain} .= '.keychain' 
          unless $self->{keychain} =~ /\.keychain$/;
    } 

    # Some test operation
    my $reply = capturex($self->_make_sys_args(
        "-q",
        "show-keychain-info"));

    return $self;
}

# Prepares args by prefixing with command and suffixing with keychain
# if specified
sub _make_sys_args {
    my ($self, @args) = @_;
    unshift @args, $self->{security};
    push @args, $self->{keychain} if $self->{keychain};
    return @args;
}

=head2 set_password(username, password, realm)

Sets (stores) password identified by given realm for given user 

=cut

sub set_password {
    my ($self, $user_name, $user_password, $realm) = @_;

    # TODO: maybe use -l (label) instead of -D
    systemx($self->_make_sys_args(
        "-q", # quiet
        "add-generic-password",
        "-a", $user_name,
        "-s", $realm,
        "-D", $self->{group}, # "kind", can be used to match so let be
        "-w", $user_password,
        "-j", $self->{app}, # comment
        "-A", # any app can access
        "-U", # allow update
        ));
}

sub _parse_password_from_find_output {
    my ($text) = @_;

    if($text =~ /^ *password: *"([^"]*)"/m)  {
        return $1;
    }
    elsif($text =~ /^ *password: *\$([0-9A-Fa-f]*)/m) {
        return pack("H*", $1);
    }
    elsif($text =~ /^ *password: *$/m)  {
        return "";
    }

}

=head2 get_password($user_name, $realm)

Reads previously stored password for given user in given app.
If such password can not be found, returns undef.

=cut

sub get_password {
    my ($self, $user_name, $realm) = @_;

    my $reply = capturex($self->_make_sys_args(
        "-q", # quiet
        "find-generic-password",
        "-a", $user_name,
        "-s", $realm,
        "-D", $self->{group}, # "kind", can be used to match so let be
        "-g", # display the password
        ));

    return _parse_password_from_find_output($reply);
}

=head2 clear_password($user_name, $realm)

Removes given password (if present)

Returns how many passwords actually were removed 

=cut

sub clear_password {
    my ($self, $user_name, $realm) = @_;

    my $reply = systemx($self->_make_sys_args(
        "delete-generic-password",
        "-a", $user_name,
        "-s", $realm,
        "-D", $self->{group}, # "kind", can be used to match so let be
        ));

}

=head2 is_persistent

Returns info, whether this keyring actually saves passwords persistently.

(true in this case)

=cut

sub is_persistent {
    my ($self) = @_;
    return 1;
}


=head1 AUTHOR

Marcin Kasperski

=head1 BUGS

Please report any bugs or feature requests to 
issue tracker at L<https://bitbucket.org/Mekk/perl-keyring-osxkeychain>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Passwd::Keyring::OSXKeychain

You can also look for information at:

L<http://search.cpan.org/~mekk/Passwd-Keyring-OSXKeychain/>

Source code is tracked at:

L<https://bitbucket.org/Mekk/perl-keyring-osxkeychain>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Marcin Kasperski.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1; # End of Passwd::Keyring::OSXKeychain

