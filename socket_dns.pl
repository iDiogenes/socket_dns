#!/usr/bin/perl -w
#
# socket_dns.pl v0.1 (JD Trout)
#
# This script should do the following:
#
#  1. Check to see if SSH port is up on specified servers.
#
#  2. Make sure DNS reflects the hosts who are up.              
#
#  3. Email administrator if host is no longer in DNS.
use Net::DNS;
use IO::Socket;
use strict;

# Fix output
$| = 1;

my %files; 
my %config;

$files{'config'} = "/etc/socket_dns.conf";

my $debug = 0;
my $shutdown = 0;
my $daemon = 0;

#Command line args
foreach(@ARGV) {
  if(/^\-d$/) { $daemon = 1; }
  if(/^\-v$/) { $debug = 1; }
  if(/^\-s$/) { $shutdown = 1; }
  if(/^\-shutdown$/) { $shutdown = 1; }
}

##############
# Sub routines
##############
# Get Config
sub get_config {

	#Read in Config
	open(CONFIG, $files{'config'}) or die ("Can't open config file!");
	my @listlines = <CONFIG>;
	close(CONFIG);

	my @clean;

	foreach(@listlines) {
		# Put a newline before and after every brace
		#s/([{}]/\n\1\n/g;
		# Blank line
		if(/^[\n\t\ ]+$/) { next; }
		# Pure Comments
		if(/^[\n\t\ ]#.*/) { next; }
		# Remove comments
		s/#.*//;
		# Remove Leading / trailing space
		s/^[\ \t]+//;
		s/[\ \t]+$//;

		#Advanced chomp
		s/\n+$//;

		my @lines = split(/\n/, $_);
		foreach(@lines) {
			# Blank lines
			if(/^[\n\t\ ]+$/) { next; }
			if(/^$/) { next; }
			s/\n+$//;
			push(@clean, "$_\n");
		}
	}

	my $section = 0;
	# Hash Pointer
	my $p_hash;
	my $depth = 0;

	foreach(@clean) {
		chomp;
		if($section) {
			if(/\}/) { $depth -= 1; }
			if($depth) {
				# Parse out a name = value
				/^\s*([\w\-\._]+)\s*=\s*"?(.+?)"?\s*$/ && do {
			    	$p_hash->{$1} = $2;
			    }
			}
			if(/\{/) { $depth += 1; }
			unless($depth) {
				$section = 0;
			}
		}
		else {
			# Find sections
			if(/^\[(.*)\]$/) {
				my $sectioni_name;
				my $section_name = $_ = $1;
				if(/files/) {
					$section = 1;
					$depth = 0;
					$p_hash = \%files;
				}
				elsif(/global/) {
					$section = 1;
					$depth = 0;
					$p_hash = \%config;
				}
			}
		}
	}
	# End foreach(@clean)
	
	if($files{'output'}) {
		my $output;
		$output = $files{'output'} . $output;
	}

	return 1;
}

# Socket Check
sub socket_check {
	my $ip = shift;
	my $port = shift;
	my $proto = $config{'query_proto'};
	my $sock = new IO::Socket::INET (PeerAddr => $ip,
                                       PeerPort => $port,
                                       Proto    => $proto);
    if ($sock) {		# Socket is good.
    	close $sock;
		&write_log("Socket for $ip is active.");
		print "Socket for $ip is active. \n" if $debug;
		return 1;
   	}
   	else {
   	   		&write_log ("Socket for $ip is down.");
   	   		print "Socket for $ip is down. \n";
			return 0;
	}
}
# DNS check 
sub dns_check {

  #Defining necessary variables
  my $ip = shift;
  my $res = new Net::DNS::Resolver;
  #Query the name server for the hostname.
  if (my $query = $res->query($config{'query_hostname'})) {
    foreach $_ ($query->answer) {
      next unless $_->type eq "A";
      my $address = $_->address;
        if ($address eq $ip) {
          return 1;
			    print "Query return of IP is: $ip \n" if $debug;
        }
        else {
          print "Query IP $ip is not matching $address \n" if $debug;
        }  
    }

  }

  else {
    &write_log ("$ip is no longer in DNS, or socket_dns.pl can no longer query DNS.");
	  &email ("$ip is no longer in DNS, or socket_dns.pl can no longer query DNS.");
  }
}


# Add DNS Record
sub dns_add {

  #Defining necessary variables
  my $ip = shift;
  my $res = new Net::DNS::Resolver;
  my $update = new Net::DNS::Update($config{'dns_zone'});
  my $key_name = $config{'dns_key_name'};
  my $key = $config{'dns_key'};            
  my $tsig = Net::DNS::RR->new("$key_name TSIG $key");
  $tsig->fudge(60);

  # Write update to log
  &write_log("Adding host $config{'query_hostname'} with IP $ip to DNS");  #Throwing error

  #Add the A record 
  $update->push(update => rr_add("$config{'query_hostname'} 180 A $ip"));
  $update->sign_tsig($tsig);
  $res->nameservers($config{'dns_servers'});
  my $ans = $res->send($update);
   
  # Check to make sure record was added.
  if (defined $ans) {
	  if ($ans->header->rcode eq "NOERROR") {
      &write_log("$ip  added successfully to DNS.");
    }
	  else {
      &write_log("Return code: '$ans->header->rcode'");
      &write_log( "Failed to add $ip to DNS.");
      &email("Failed to add  $ip to DNS. \n Return code: '$ans->header->rcode'");
    }
  }
  else {
    &write_log("Error: '$res->errorstring'");
    &write_log("Failed to add $ip to DNS.");
	  &email("Failed to add  $ip to DNS. \n 
            Error: $res->errorstring \n");	
    print "Error $res->errorstring \n when trying to DNS record for IP $ip" if $debug;
  }
}

#Remove DNS
sub dns_del {		

  #Defining necessary variables
  my $ip = shift;
  my $res = new Net::DNS::Resolver;
  my $update = new Net::DNS::Update($config{'dns_zone'});
  my $key_name = $config{'dns_key_name'};
  my $key = $config{'dns_key'};          
  my $tsig = Net::DNS::RR->new("$key_name TSIG $key");
  $tsig->fudge(60);

  # Write update to log
  &write_log("Removing host $config{'query_hostname'} with IP $ip from DNS");
  print "Removing host $config{'query_hostname'} from zone $config{'dns_zone'}, with IP $ip from DNS \n";
  
  #Remove the A record
  $update->push(update => rr_del("$config{'query_hostname'} A $ip" ));
  $update->sign_tsig($tsig);
  $res->nameservers($config{'dns_servers'});
  my $ans = $res->send($update);
   
  # Check to make sure record was added.
  if (defined $ans) {
    if ($ans->header->rcode eq "NOERROR") {
      &write_log("$ip removed successfully from DNS.");
      print "$ip removed successfully from DNS.\n" if $debug;
    }
    else {
      &write_log("Return code:,'$ans->header->rcode,'");
      &write_log( "Failed to remove $ip From DNS.");
		  &email("Failed to remove  $ip from DNS. \n Return code: '$ans->header->rcode'");
      print "Failed to remove IP $ip.\n Return Code:", $ans->header->rcode, "\n" if $debug;
    }
  }
  else {
    &write_log("Error: '$res->errorstring'");
    &write_log("Failed to remove $ip from DNS.");
	  &email("Failed to remove  $ip from DNS. \n Error: '$res->errorstring' \n");	
  }
}

#DNS Safety
sub dns_safety_check {
	my @query_host_ip = split(/\ /, $config{'query_host_ip'});
	my $dns_count;
	foreach(@query_host_ip) {
		if (&dns_check($_) ) {
			$dns_count++;
		}
		else {
			&write_log("DNS Safety shows that $_ does not exists in DNS.");
			print "DNS Safety shows that $_ does not exists in DNS. \n" if $debug;
		}
	}		
	if ($dns_count == 2) {
		return 1;
	}
	else {
		return 0;
	}
}

#Logging
sub write_log {
  my $message = shift;
  open(LOG, ">>$files{'log'}");
  print LOG &format_time(time) . ": $message\n";
  close(LOG);
}

#Format time
sub format_time {
  my($sec, $min, $hour, $mday, $mon) = localtime($_[0]);
  my($fmt_mon) = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')[$mon];
  return(sprintf("%s %d %.2d:%.2d:%.2d", $fmt_mon, $mday, $hour, $min, $sec));
}

# Email critical Errors
sub email {
  my $body = shift;
  my $subject = "[loni-sys] SSH IP Mgmt issue!";

  #Send email
  system("echo \"$body\" | mailx -s \"$subject\" sysadm\@sub.domain.com"); 
}

# Shutdown the daemon
sub shutdown_daemon {
  open(PID, $files{'pid'});
  my $pid = <PID>;
  close(PID);
  chomp $pid;
  if($pid) {
    print "Killing process $pid\n";
    &write_log("Killing process $pid\n");
    sleep(1);
    system("kill $pid");
  }
  else {
    &write_log("No process found \n");
    print "No process found\n";
  }
  exit;
}

sub execute {
  # Interval (in seconds) to perform check.
	my $interval = shift;
	while(1) {
		&function();
		sleep($interval);
	}		
}

sub function {
  my $ports = $config{'query_ports'};	
  my @query_host_ip = split(/\ /, $config{'query_host_ip'});	
  my $query;
	foreach(@query_host_ip) {
		my $sock = &socket_check($_, $ports);
		my $query = &dns_safety_check();
		unless ($sock > 0) { 
			&write_log ("Socket check for $_ failed!  Trying again in 20 seconds.");
			print "Socket check for $_ failed!  Trying again in 20 seconds. \n" if $debug;
			sleep 20;
			$sock = &socket_check($_, $ports);
		}
		if ($query > $sock) {
			my $dns_safety = &dns_safety_check();
			while($dns_safety) {
				&write_log ("Socket is down but DNS exists.  Removing DNS for $_.");
				print "Socket is down but DNS exists.  Removing DNS for $_. \n" if $debug;
				&dns_del($_);
				last;
			}
		}
		elsif ($sock > $query) {
			&write_log ("Socket is up but DNS does not exists.  Adding DNS for $_.");
			print "Socket is up but DNS does not exists.  Adding DNS for $_.";
			&dns_add($_);
		}
	}
}
                        
##########
# Program exe
##########

&get_config();	

if($shutdown) {
  &shutdown_daemon();
  exit;
}

if($daemon) {
  my $interval = $config{'query_interval'};
  FORK: {
    if(my $pid = fork) {
      &write_log("Starting socket_dns.pl ($pid)");
      print "Starting socket_dns.pl ($pid)" if $debug;
      exit;
    }
	elsif (defined $pid) {
      &write_log("Child started ($$)");
      open(PIDFILE, ">" . $files{'pid'} ) || do
        {
          &write_log("Cannot write to $files{'pid'}, exiting");
          print "Cannot write to $files{'pid'}, exiting" if $debug;
          exit;
        };
		print PIDFILE "$$";
      	close(PIDFILE);

        &execute($interval);
        &write_log("Execute loop closed, process ending");
        print "Execute loop closed, process ending" if $debug;
	}
    elsif ($! =~ /No more process/) {
      sleep 5;
      redo FORK;
    }
    else {
      die 'Cannot fork: $!\n';
    }
  }
}
else {
  &function(); 
  exit;
}
