package Net::Nessus::XMLRPC;

use XML::Simple;
use LWP::UserAgent;
use HTTP::Request::Common;

use warnings;
use strict;

=head1 NAME

Net::Nessus::XMLRPC - Communicate with Nessus scanner(v4.2+) via XMLRPC

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';


=head1 SYNOPSIS

This is Perl interface for communication with Nessus scanner over XMLRPC.
You can start, stop, pause and resume scan. Watch progress and status of 
scan, download report, etc.

    use Net::Nessus::XMLRPC;

    use strict;

    # '' is same as https://localhost:8834/
    my $n = Net::Nessus::XMLRPC->new ('','user','pass');
    my $scanid;

    $SIG{INT} = \&ctrlc;

    if ($n->logged_in) {
	    print "Logged in\n";
	    my $polid=$n->policy_get_first;
	    print "Using policy ID: $polid ";
	    my $polname=$n->policy_get_name($polid);
	    print "with name: $polname\n";
	    $scanid=$n->scan_new($polid,"perl-test","127.0.0.1");
	    while (not $n->scan_finished($scanid)) {
		    print "Status of $scanid: ".$n->scan_status($scanid)."\n";
		    sleep 10;
	    }
	    print "Status of $scanid: ".$n->scan_status($scanid)."\n";
	    
    } else {
	    print "URL, user or password not correct: ".$n->nurl."\n";
    }

    sub ctrlc {
	    $SIG{INT} = \&ctrlc;
	    print "\nCTRL+C presssed, stopping scan.\n";
	    $n->scan_stop($scanid);
    }

=head1 METHODS

=head2 new ([$nessus_url], [$user], [$pass])

creates new object Net::Nessus::XMLRPC
=cut
sub new {
	my $class = shift;

	my $self; 

	$self->{_nurl} = shift;
	if ($self->{_nurl} eq '') {
		$self->{_nurl}='https://localhost:8834/';
	} elsif (substr($self->{_nurl},-1,1) ne '/') {
		$self->{_nurl}= $self->{_nurl}.'/';	
	} 
	my $user = shift;
	my $password = shift;
	$self->{_token} = undef;
	$self->{_name} = undef;
	$self->{_admin} = undef;
	$self->{_ua} = LWP::UserAgent->new;
	bless $self, $class;
	if ($user and $password) {
		$self->login($user,$password);
	}
	return $self;
}

=head2 nurl ( [$nessus_url] )

get/set Nessus base URL
=cut
sub nurl {
	my ( $self, $nurl ) = @_;
	$self->{_nurl} = $nurl if defined($nurl);
	return ( $self->{_nurl} );
}

=head2 token ( [$nessus_token] )

get/set Nessus login token
=cut
sub token {
	my ( $self, $token ) = @_;
	$self->{_token} = $token if defined($token);
	return ( $self->{_token} );
}

=head2 nessus_http_request ( $uri, $post_data )

low-level function, makes HTTP request to Nessus URL	
=cut
sub nessus_http_request {
	my ( $self, $uri, $post_data ) = @_;
	my $ua = $self->{_ua};
	# my $ua = LWP::UserAgent->new;
	my $furl = $self->nurl.$uri;
	my $r = POST $furl, $post_data;
	my $result = $ua->request($r);
	if ($result->is_success) {
		return $result->content;
	} else {
		return '';
	}
}

=head2 nessus_request ($uri, $post_data) 

low-level function, makes XMLRPC request to Nessus URL and returns XML
=cut
sub nessus_request {
	my ( $self, $uri, $post_data ) = @_;
	my $cont=$self->nessus_http_request($uri,$post_data);
	if ($cont eq '') {
		return ''	
	}
	my $xmls;
	eval {
	$xmls=XMLin($cont, ForceArray => 1, KeyAttr => '');
	} or return '';
	if ($xmls->{'status'}->[0] eq "OK") {
		return $xmls; 
	} else { 
		return ''
	}
}

=head2 login ( $user, $password )

login to Nessus server via $user and $password	
=cut
sub login {
	my ( $self, $user, $password ) = @_;

	my $post=[ login => $user, password => $password ];
	my $xmls = $self->nessus_request("login",$post);

	if ($xmls eq '' or not defined($xmls->{'contents'}->[0]->{'token'}->[0])) {
		$self->token('');
	} else {
		$self->token ($xmls->{'contents'}->[0]->{'token'}->[0]);
	}
	return $self->token;
}

=head2 logged_in

returns true if we're logged in
=cut
sub logged_in {
	my ($self) = @_;
	return $self->token;
}

=head2 scan_new ( $policy_id, $scan_name, $targets )

initiates new scan 
=cut
sub scan_new {
	my ( $self, $policy_id, $scan_name, $target ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"policy_id" => $policy_id,
		"scan_name" => $scan_name,
		"target" => $target
		 ];

	my $xmls = $self->nessus_request("scan/new",$post);
	if ($xmls) {
		return ($xmls->{'contents'}->[0]->{'scan'}->[0]->{'uuid'}->[0]);
	} else {
		return $xmls
	}
}	

=head2 scan_stop ( $scan_id )

stops the scan identified by $scan_id
=cut
sub scan_stop {
	my ( $self, $scan_uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"scan_uuid" => $scan_uuid,
		 ];

	my $xmls = $self->nessus_request("scan/stop",$post);
	return $xmls;
}

=head2 scan_stop_all 

stops all scans
=cut
sub scan_stop_all {
	my ( $self ) = @_;

	my @list = $self->scan_list_uids;

	foreach my $uuid (@list) {
		$self->scan_stop($uuid);
	}
	return @list;
}

=head2 scan_pause ( $scan_id )

pauses the scan identified by $scan_id
=cut
sub scan_pause {
	my ( $self, $scan_uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"scan_uuid" => $scan_uuid,
		 ];

	my $xmls = $self->nessus_request("scan/pause",$post);
	return $xmls;
}

=head2 scan_pause_all 

pauses all scans
=cut
sub scan_pause_all {
	my ( $self ) = @_;

	my @list = $self->scan_list_uids;

	foreach my $uuid (@list) {
		$self->scan_pause($uuid);
	}
	return @list;
}

=head2 scan_resume ( $scan_id )

resumes the scan identified by $scan_id
=cut
sub scan_resume {
	my ( $self, $scan_uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"scan_uuid" => $scan_uuid,
		 ];

	my $xmls = $self->nessus_request("scan/resume",$post);
	return $xmls;
}

=head2 scan_resume_all 

resumes all scans
=cut
sub scan_resume_all {
	my ( $self ) = @_;

	my @list = $self->scan_list_uids;

	foreach my $uuid (@list) {
		$self->scan_resume($uuid);
	}
	return @list;
}

=head2 scan_list_uids 

returns array of IDs of (active) scans
=cut
sub scan_list_uids {
	my ( $self ) = @_;

	my $post=[ 
		"token" => $self->token
	];

	my $xmls = $self->nessus_request("scan/list",$post);
	my @list;
	if ($xmls->{'contents'}->[0]->{'scans'}->[0]->{'scanList'}->[0]->{'scan'}) {
	foreach my $scan (@{$xmls->{'contents'}->[0]->{'scans'}->[0]->{'scanList'}->[0]->{'scan'}}) {
		push @list, $scan->{'uuid'}->[0];
	} # foreach
	return @list;
	} # if
}

=head2 scan_get_name ( $uuid ) 

returns name of the scan identified by $uuid 
=cut
sub scan_get_name {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token
	];

	my $xmls = $self->nessus_request("scan/list",$post);
	if ($xmls->{'contents'}->[0]->{'scans'}->[0]->{'scanList'}->[0]->{'scan'}) {
	foreach my $scan (@{$xmls->{'contents'}->[0]->{'scans'}->[0]->{'scanList'}->[0]->{'scan'}}) {
		if ($scan->{'uuid'}->[0] eq $uuid) {
			return $scan->{'readableName'}->[0];
		}
	} # foreach
	} # if
}

=head2 scan_status ( $uuid ) 

returns status of the scan identified by $uuid 
=cut
sub scan_status {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"report" => $uuid,
		 ];

	my $xmls = $self->nessus_request("report/list",$post);
	if ($xmls->{'contents'}->[0]->{'reports'}->[0]->{'report'}) {
	foreach my $report (@{$xmls->{'contents'}->[0]->{'reports'}->[0]->{'report'}}) {
		if ($report->{'name'}->[0] eq $uuid) {
			return $report->{'status'}->[0];
		}
	} # foreach
	} # if
	return ''; # nothing found
}

=head2 scan_finished ( $uuid ) 

returns true if scan is finished/completed (identified by $uuid)
=cut
sub scan_finished {
	my ( $self, $uuid ) = @_;
	my $status = $self->scan_status($uuid);
	if ( $status eq "completed" ) {
		return $status;
	} else {
		return '';
	}
}	

=head2 policy_get_first

returns policy id for the first policy found
=cut
sub policy_get_first {
	my ( $self ) = @_;

	my $post=[ 
		"token" => $self->token, 
		 ];
	
	my $xmls = $self->nessus_request("policy/list",$post);
	if ($xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}) {
	foreach my $report (@{$xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}}) {
		return $report->{'policyID'}->[0];
	} # foreach
	} # if
	return '';
}

=head2 policy_list_uids 

returns array of IDs of policies available
=cut
sub policy_list_uids {
	my ( $self ) = @_;

	my $post=[ 
		"token" => $self->token, 
		 ];

	my $xmls = $self->nessus_request("policy/list",$post);
	my @list;
	if ($xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}) {
	foreach my $report (@{$xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}}) {
		push @list,$report->{'policyID'}->[0];
	} # foreach
	return @list;
	} # if
	return '';
}

=head2 policy_list_names 

returns array of names of policies available
=cut
sub policy_list_names {
	my ( $self ) = @_;

	my $post=[ 
		"token" => $self->token, 
		 ];

	my $xmls = $self->nessus_request("policy/list",$post);
	my @list;
	if ($xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}) {
	foreach my $report (@{$xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}}) {
		push @list,$report->{'policyName'}->[0];
	} # foreach
	return @list;
	} # if
	return '';
}

=head2 policy_get_id ( $policy_name ) 

returns ID of the policy identified by $policy_name 
=cut
sub policy_get_id {
	my ( $self, $policy_name ) = @_;

	my $post=[ 
		"token" => $self->token, 
		 ];
	 my $xmls = $self->nessus_request("policy/list",$post);
	 if ($xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}) {
	 foreach my $report (@{$xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}}) {
		if ($report->{'policyName'}->[0] eq $policy_name) {
			return $report->{'policyID'}->[0];
		}
	 } # foreach
	 } # if
	 return '';
}

=head2 policy_get_name ( $policy_id ) 

returns name of the scan identified by $policy_id 
=cut
sub policy_get_name {
	my ( $self, $policy_id ) = @_;

	my $post=[ 
		"token" => $self->token, 
		 ];
	 my $xmls = $self->nessus_request("policy/list",$post);
	 if ($xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}) {
	 foreach my $report (@{$xmls->{'contents'}->[0]->{'policies'}->[0]->{'policy'}}) {
		if ($report->{'policyID'}->[0] eq $policy_id) {
			return $report->{'policyName'}->[0];
		}
	 } # foreach
	 } # if
	 return '';
}

=head2 report_list_uids 

returns array of IDs of reports available
=cut
sub report_list_uids {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"report" => $uuid,
		 ];

	my $xmls = $self->nessus_request("report/list",$post);
	my @list;
	if ($xmls->{'contents'}->[0]->{'reports'}->[0]->{'report'}) {
	foreach my $report (@{$xmls->{'contents'}->[0]->{'reports'}->[0]->{'report'}}) {
		push @list, $report->{'name'}->[0];
	}
	}

	return @list;
}

=head2 report_file_download ($report_id)

returns XML report identified by $report_id (Nessus XML v2)
=cut
sub report_file_download {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"report" => $uuid,
		 ];

	my $file = $self->nessus_http_request("file/report/download", $post);
	return $file;
}	

=head2 report_file1_download ($report_id)

returns XML report identified by $report_id (Nessus XML v1)
=cut
sub report_file1_download {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"report" => $uuid,
		"v1" => "true",
		 ];

	my $file = $self->nessus_http_request("file/report/download", $post);
	return $file;
}	

=head2 report_delete ($report_id)

delete report identified by $report_id
=cut
sub report_delete {
	my ( $self, $uuid ) = @_;

	my $post=[ 
		"token" => $self->token, 
		"report" => $uuid,
		 ];

	my $xmls = $self->nessus_request("report/delete", $post);
	return $xmls;
}	

=head1 AUTHOR

Vlatko Kosturjak, C<< <kost at linux.hr> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-nessus-xmlrpc at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Nessus-XMLRPC>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Nessus::XMLRPC


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Nessus-XMLRPC>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Nessus-XMLRPC>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Nessus-XMLRPC>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Nessus-XMLRPC>

=back


=head1 REPOSITORY

Repository is available on GitHub: http://github.com/kost/nessus-xmlrpc-perl

=head1 ACKNOWLEDGEMENTS

I have made Ruby library as well: http://nessus-xmlrpc.rubyforge.org/

There you can find some early documentation about XMLRPC protocol used.

=head1 COPYRIGHT & LICENSE

Copyright 2010 Vlatko Kosturjak, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1; # End of Net::Nessus::XMLRPC
