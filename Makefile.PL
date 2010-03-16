use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Nessus::XMLRPC',
    AUTHOR              => 'Vlatko Kosturjak <kost@linux.hr>',
    VERSION_FROM        => 'lib/Net/Nessus/XMLRPC.pm',
    ABSTRACT_FROM       => 'lib/Net/Nessus/XMLRPC.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-Nessus-XMLRPC-*' },
);
