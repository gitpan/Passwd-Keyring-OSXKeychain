use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Passwd::Keyring::OSXKeychain',
    license             => 'perl',
    dynamic_config      => 1,

    build_requires => {
        'Module::Build' => '0.19', # xs
        'Test::More' => 0,
        'Test::Pod::Coverage' => '1.0',
    },
    configure_requires => {
        'Module::Build' => '0.36',
    },
    requires => {
        'perl' => 5.006,
        'IPC::System::Simple' => '1.18',
    },

    create_makefile_pl => 'traditional',
    add_to_cleanup      => [ 'Passwd-Keyring-OSXKeychain-*' ],

    create_readme       => 1,
    dist_author         => q{Marcin Kasperski <Marcin.Kasperski@mekk.waw.pl>},
    dist_version_from   => 'lib/Passwd/Keyring/OSXKeychain.pm',
    meta_merge => {
        keywords => [ qw/ passwords security secure-storage keyring Mac OSX keychain keyring / ],
        resources => {
            license     => 'http://dev.perl.org/licenses/',
            homepage    => 'http://bitbucket.org/Mekk/perl-keyring-osxkeychain',
            repository => 'http://bitbucket.org/Mekk/perl-keyring-osxkeychain',
            bugtracker => 'https://bitbucket.org/Mekk/perl-keyring-osxkeychain/issues',
        },
    },
);

$builder->create_build_script();
