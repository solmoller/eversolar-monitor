#! /usr/bin/perl
#
# bugs to fix : warnings, double entries  to pvlog, max of the day
#
# Eversolar inverter data logger
# - Based on Steve Cliffe's <steve@sjcnet.id.au> Eversolar PMU logger script (http://www.sjcnet.id.au/computers/eversolar-inverter-monitoring-with-linux)
# - Tested and known to work with the following inverters:
# -- TL1500AS Inverter connected to an ethernet to serial converter
# -- TL2000 (multiple) connected to a Raspberry Pi
# -- TL3000 (multiple) connected to a Raspberry Pi
# -- Volta TL3000
# - Supports upload of data to pvoutput.org. Please consider joining the "Eversolar perl loggers" team if you use this script - http://pvoutput.org/ladder.jsp?tid=485
#
# Kayne Richens <kayno@kayno.net>
#
# Version 0.1 - September 30 2011
#       - first release
# Version 0.2 - October 03 2011
#	- fixed bug that stopped script when inverter shut down at night
#       - moved config options to a config file (eversolar.ini)
#       - added support for direct serial comms (no eth2ser converter) - NOT TESTED!
#	- added "-m 30" (max run time 30 seconds) to curl so script doesn't hang when pvoutput.org goes down
# Version 0.3 - October 12 2011
#	- added support to upload generation to smartenergygroups.com (SEG)
# Version 0.4 - October 16 2011
#	- added a http server, so the inverter can be accessed via the browser
#	- experimental multiple inverter support started - not working yet
# Version 0.5 - October 26 2011
#	- added paging to web server /log request
# Version 0.6 - November 18 2011
#	- more fixes to inverter re-connect after overnight shutdown
#	- added max daily PAC to web interface
# Version 0.7 - November 20 2011
#	- added debugs to help with inverter re-connect after overnight shutdown
#	- added the time that the max daily PAC occured to web interface
# Version 0.8 - November 21 2011
#	- fixed bug in 0.7 that stopped inverter connecting
# Version 0.9 - November 23 2011
#	- added a sleep after inverter wakes and powers up the ethernet to serial converter, to allow it time before initiating the connection
#	- fixed the log display in the web interface when the log is not stored in the default location
# Version 0.10 - June 7 2012
#       - added temp and volts (PV) to pvoutput.org upload
#
#   Code move to http://code.google.com/p/eversolar-monitor/ - August 31 2012
#
#
# Version 0.11 - March 28 2013  by Claus Stenager
#    - added summary of more inverters, requires change in index.html
# Version 0.12 - April 21 2013  by Henrik Jørgensen
#    - added output to pv-log.com
#    - fixed ripple on pvoutput with more inverters due to global min in pmu_log - hat tip leifnel
#    - fixed temperature bug on negative centigrades - leifnel 
#    - faster connections from  multiple inverters, as we are polling aggresively if no inverters are connected
#    - It's now possible to specify an ini file from command line - Mads Lie Jensen
#    - Moved web server back into mail pl file to encompass the ini file specified from command line
#    - several minor changes, cleaning up code 
#    - fixed issue with max production today
#    - stopped deleting the webfile when last inverter shut down, effectively enabling the webpage after inverter shut down
#    - Added severity to logging, and only writes to logfile if debugging is set sufficiently high
#      Severity 1 is high severity, severity 3 is an informal message, setting debug to 3 creates a very long logfile, and slows web interface with lots of unimportant messages
# Version 0.13 - April 21 2013  by Henrik Jørgensen
#    - Now even faster connect, as it picks out serial numbers from database for immediate connection to inverters - Morten Friis
#    - A few minor bugfixes
# Version 0.14 - Jan 31st 2015  by Henrik Jørgensen
#    - Updated to handle total production over 6553,5 KWh by reading and adding two further bytes of production data
#
#   Code move to https://github.com/solmoller/eversolar-monitor - August 20 2015
#
# Version 0.15 - Sep 5th 2015  by Henrik Jørgensen
#    -  Bugfix september 5th 2015 for serial numbers containing null
# Version 0.16 - January 21th 2017
#       - added rolling 365 days production (not a year, as leap years will skew data)
# Version 0.17 - december 3rd 2017 by Henrik Jørgensen
#       - updated rolling 365 days to update historical data more intelligently
#       - added Domoticz integration
#
#
#
# Eversolar communications packet definition:
# 0xaa, 0x55, 	# header
# 0x00, 0x00, 	# source address
# 0x00, 0x00, 	# destination address
# 0x00, 	# control code
# 0x00, 	# function code
# 0x00, 	# data length
# 0x00...0x00	# data
# 0x00, 0x00 	# checksum
#

use IO::Socket::INET;
use AppConfig;
use JSON;
use DBI;
use Net::FTP;
use File::Copy;
#use warnings;

our $config = AppConfig->new();
$config->define("eth2ser_ip_address=s");
$config->define("eth2ser_port=s");
$config->define("serial_port=s");
$config->define("pvoutput_enabled=s");
$config->define("pvoutput_api_key=s");
$config->define("pvoutput_system_id=s%");
$config->define("pvoutput_status_interval_mins=s");
$config->define("pvoutput_add_status_url=s");
$config->define("options_debug=s");
$config->define("options_query_inverter_secs=s");
$config->define("options_log_file=s");
$config->define("options_communication_method=s");
$config->define("options_strings=s");
$config->define("pvlog_enabled=s");
$config->define("pvlog_FTPServeradresse=s");
$config->define("pvlog_interval=s");
$config->define("pvlog_username=s");
$config->define("pvlog_Password=s");
$config->define("seg_enabled=s");
$config->define("seg_upload_interval_mins=s");
$config->define("seg_site_id=s");
$config->define("seg_device=s");
$config->define("seg_power_stream=s");
$config->define("seg_energy_stream=s");
$config->define("seg_api_url=s");
$config->define("web_server_enabled=s");
$config->define("web_server_port=s");
#$config->file("eversolar.ini");

$config->define("configFile=s");
$config->args();
 
if ($config->configFile eq '') {
    $config->configFile('eversolar.ini');
}
 
-e $config->configFile or die "Configfile '", $config->configFile, "' not found\n";
 
$config->file($config->configFile);
pmu_log("Severity 3, Configfile is: " . $config->configFile . "\n");


%CTRL_FUNC_CODES = (
	"REGISTER" => { # CONTROL CODE 0x10
		"OFFLINE_QUERY"	=> { 
			"REQUEST" => [0x10, 0x00],
			"RESPONSE" => [0x10, 0x80]
		},
		"SEND_REGISTER_ADDRESS" => {
			"REQUEST" => [0x10, 0x01],
			"RESPONSE" => [0x10, 0x81]
		},
		"RE_REGISTER" => {
			"REQUEST" => [0x10, 0x04],
			"RESPONSE" => ""
		}
	},
	"READ" => { # CONTROL CODE 0x11
		"QUERY_INVERTER_ID" => {
			"REQUEST" => [0x11, 0x03],
			"RESPONSE" => [0x11, 0x83]
		},
		"QUERY_NORMAL_INFO" => {
			"REQUEST" => [0x11, 0x02],
			"RESPONSE" => [0x11, 0x82]
		},
		"QUERY_DESCRIPTION" => {
			"REQUEST" => [0x11, 0x00],
			"RESPONSE" => [0x11, 0x80]
		},
	},
	"WRITE" => { # CONTROL CODE 0x12
	},
	"EXECUTE" => { # CONTROL CODE 0x13
	}
);


if($config->options_strings == 1) {
    %DATA_BYTES = (
        "TEMP"        => 0,
        "E_TODAY"     => 1,
        "VPV"         => 2,
        "IPV"         => 3,
        "IAC"         => 4,
        "VAC"         => 5,
        "FREQUENCY"   => 6,
        "PAC"         => 7,
        "IMPEDANCE"   => 8,
        "NA_1"        => 9,
        "E_TOTAL"     => 10,
        "NA_2"        => 11,
        "HOURS_UP"    => 12,
        "OP_MODE"     => 13
    );
} elsif($config->options_strings == 2) {
    %DATA_BYTES = (    
        "TEMP"		=> 0,
        "E_TODAY"	=> 1,
        "VPV" 		=> 2,
        "VPV2"		=> 3,
        "IPV" 		=> 4,
        "IPV2"		=> 5,
        "IAC"		=> 6,
        "VAC"		=> 7,
        "FREQUENCY"	=> 8,
        "PAC"		=> 9,
        "NA_0"		=> 10,
        "NA_1"		=> 11, # NA_1 is actually upper bytes of total production
        "E_TOTAL"	=> 12,
        "NA_2"		=> 13,
        "HOURS_UP"	=> 14,
        "OP_MODE"	=> 15
    );
} else {
    die "Incorrect config option for 'strings'\n";
}

use constant START_INVERTER_ADDRESS => 0x10; # start at 10 - giving us 244 available addresses
use constant OUR_ADDRESS => 0x01;

our $sock = 0;
our $last_min = -1;
our $pvlog_last_min =-1;
our $e_last_wh = -1;

our $next_inverter_address = START_INVERTER_ADDRESS;
our %inverters;

our $dbh = DBI->connect("dbi:SQLite:db.sqlite");

##
## sub routines
##

##
## Web server package
##

if($config->web_server_enabled) 
{
    package SolarWebServer;

    use HTTP::Server::Simple::CGI;
    use base qw(HTTP::Server::Simple::CGI);
    use JSON;
    use AppConfig;


    my %dispatch = (
        '/' => \&index,
        '/inverter-data' => \&inverter_data,
        '/log' => \&log,
        # ...
    );

    sub handle_request {
        my $self = shift;
        my $cgi  = shift;

        my $path = $cgi->path_info();
        my $handler = $dispatch{$path};

        if (ref($handler) eq "CODE") {
            print "HTTP/1.0 200 OK\r\n";
            $handler->($cgi);
        } else {
            print "HTTP/1.0 404 Not found\r\n";
            print $cgi->header,
                $cgi->start_html('Not found'),
                $cgi->h1('Not found'),
                $cgi->end_html;
        }
    }

    sub index {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        open my $fh, "<www/index.html";
        my $data = do { local $/; <$fh> };

        print $cgi->header,
            $data;
    }

    sub inverter_data {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        print $cgi->header('application/json');

        open FILE, "</tmp/eversolar";
        while(<FILE>) {
             print $_;
        }
    }

    sub log {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        my $line_limit = 100;
        my $page = $cgi->param('page');

        print $cgi->header;

        open FILE, "<".$config->options_log_file;
        @lines = reverse <FILE>;

        my $count = 0;
        foreach $line (@lines) {
            if($count < (($page*$line_limit)+1)) {
                $count++;
                next;
            }

            print $line;
    
            if($count == ($line_limit+($page*$line_limit))) {
                last;
            } else {
                $count++;
            }
        }
    }

} 

##
## send packet to inverter
##

sub send_request {
   # Don't send if not connected
    if (!$sock) {
      return FALSE;
    };
	my $destination_address = shift;
	my ($ctrl_func_code, $data) = @_;
	%ctrl_func_code = %$ctrl_func_code;
	@data = @$data;

	my $data_length = scalar(@data);

	@tmp_packet = (0xAA, 0x55, OUR_ADDRESS, 0x00, 0x00, $destination_address, $ctrl_func_code{"REQUEST"}[0], $ctrl_func_code{"REQUEST"}[1], $data_length);
	if($data_length) {
		push(@tmp_packet, @data);
	}

	$tmp_packet_length = scalar(@tmp_packet);

	# calculate checksum
	my $checksum = 0;
	for($i = 0; $i < $tmp_packet_length; $i++) {
		$checksum += $tmp_packet[$i];
	}

	$packet = pack("C".$tmp_packet_length."n", (@tmp_packet, $checksum));

	if($config->options_debug) {
		print "sending packet to inverter... \n";
		print_bytes($packet, length($packet));
	}

	if($config->options_communication_method eq "eth2ser") {
        unless($sock->send($packet, scalar($packet))) {
			pmu_log("Severity 1, Failed to write to socket: $!");
            $sock = 0;
	        return 0;
        }
	} elsif($config->options_communication_method eq "serial") {
		$sock->write($packet);
	}

    # allow time for inverter to respond
	sleep 1;
 

	if($ctrl_func_code{"RESPONSE"} ne "") {
		if($config->options_communication_method eq "eth2ser") {
			$sock->recv($response, 256);
			#unless(defined $sock->recv($response, 256)) {
            #    pmu_log("Severity 1, Failed to read from socket: $!");
            #    $sock = 0;
            #    return 0;
            #}
		} elsif($config->options_communication_method eq "serial") {
			($count_in, $response) = $sock->read(256);
		}

		if(length($response)) {
			@recv_packet = unpack("C*", $response);

			if($config->options_debug) {
				print "received packet from inverter: \n";
				print_bytes($response, length($response));
			}

			if(validate_checksum(@recv_packet)) {
				my $len = length($response) - 11;
				my ($ctrl_code, $func_code, @data) = unpack("xxxxxxCCxC".$len."xx", $response);
#use Data::Dumper;
#print Dumper(\@data);

				if($ctrl_code == $ctrl_func_code{"RESPONSE"}[0] &&
					$func_code == $ctrl_func_code{"RESPONSE"}[1]) {
					return pack("C*", @data);
				}
			}
        }
	} else {
    	return 1;
    }

    # if we fall through to here, something isn't right!
    return 0;
}


##
## Dump a buffer in hex for debugging purposes
##

sub print_bytes {
    my $buf = shift;
    my $len = shift;
    my $line_count = 0;

    if ($len <= 0) {
        return;
    }

    my @bytes = unpack("C$len", $buf);

    if ($len > 0) {
        for (my $i=0; $i<$len; $i++) {
            printf "%02x ", $bytes[$i];
            if ($line_count++ > 15) {
                $line_count = 0;
                print "\n";
            }
        }
    }
    printf "\n";
}

##
## Connect to the ethernet-to-serial converter attached to the inverter
##

sub eth2ser_connect {
    # make sure the sock is closed
    shutdown($sock, 2);

	# connect to ethernet to serial converter attached to inverter
	# loop until it connects
	do {
		$sock = new IO::Socket::INET (
			PeerAddr => $config->eth2ser_ip_address,
			PeerPort => $config->eth2ser_port,
			Proto => 'tcp',
			);

		if ($sock) {
			pmu_log("Severity 1, Connected to the ethernet to serial converter");
		} else {
			pmu_log("Severity 2, Unable to connect to the ethernet to serial converter ... sleeping 60 seconds");
			sleep 60;
		}
	} until ($sock);

	my $timeo = pack("l!l!", 1, 0);
	$sock->sockopt(SO_RCVTIMEO, $timeo);
	$sock->sockopt(SO_SNDTIMEO, $timeo);

	# sleep to allow inverter time to ready itself for connection
	sleep 10;
}

##
## Connect directly to the inverter via serial
##

sub serial_connect {
	if ($^O eq 'MSWin32') {		# Win32 (ActivePerl)
		eval "use Win32::SerialPort";
		$sock = Win32::SerialPort->new ($config->serial_port, 0, '') || die "Can\'t open $port: $!";
	} else {				# Unix/Linux/other
		eval "use Device::SerialPort";
		$sock = Device::SerialPort->new ($config->serial_port, 0, '') || die "Can\'t open $port: $!";
	}

	$sock->baudrate(9600)	 	|| die 'fail setting baudrate, try -b option';
	$sock->parity("none") 		|| die 'fail setting parity';
	$sock->databits(8) 		|| die 'fail setting databits';
	$sock->stopbits(1) 		|| die 'fail setting stopbits';
	$sock->handshake("none") 	|| die 'fail setting handshake';
	$sock->datatype("raw") 		|| die 'fail setting datatype';
	$sock->write_settings 		|| die 'could not write settings';
	$sock->read_char_time(0);     	# don't wait for each character
	$sock->read_const_time(1000); 	# 1 second per unfulfilled "read" call
}

##
## send the re-register packet to inverters 8 times (happens after initial connect)
##

sub re_register_inverters {
	# ask all inverters to drop their registration and respond to register requests - send packet 3 times as per protocol specs
    for(my $i=0; $i<8; $i++) {
	    unless(send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"RE_REGISTER"})) {
            pmu_log("Severity 2, Failed to send re-register message");
            return 0;
        }
    }

    return 1;
}

##
## send the register packet to any inverters out there, and register inverter that responds first
##

sub register_inverter {
	# request serial numbers
	$serial_num_response = send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"OFFLINE_QUERY"});
	if($serial_num_response) {  ##bugfix september 2nd 2015 for serial numbers containing null: Z* instead of A*:
		my $serial_number = unpack("Z*", $serial_num_response);
		pmu_log("Severity 1, Found serial number: $serial_number");

		# send register address (serial number followed by 1 byte address we allocate to inverter)
		my @register_address = unpack("C*", $serial_num_response);
		push(@register_address, $next_inverter_address);
		$address_response = send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"SEND_REGISTER_ADDRESS"}, \@register_address);
		if($address_response) {
			# check register acknowledgement
    		my $len = length($address_response);
			my $register_acknowledgement = unpack("C", $address_response);
			if($register_acknowledgement == 06) {
				pmu_log("Severity 1, Inverter acknowledged registration");

				# request inverter ID 
				$inverter_id_response = send_request($next_inverter_address, $CTRL_FUNC_CODES{"READ"}{"QUERY_INVERTER_ID"});
				if($inverter_id_response) {
				    my $len = length($inverter_id_response);
					my $inverter_id = unpack("A*", $inverter_id_response);
					pmu_log("Severity 1, Connected to inverter: $inverter_id");

					# remember this inverter
	                $timestamp = get_timestamp();
					$inverters{$next_inverter_address}{"id_string"} = $inverter_id;
					$inverters{$next_inverter_address}{"serial"} = $serial_number;
					$inverters{$next_inverter_address}{"connected"} = $timestamp;
					$inverters{$next_inverter_address}{"max"} = {
						"pac" => {
							"watts" => 0,
							"timestamp" => $timestamp
						}
					};

					$next_inverter_address++;
                } else {
                    pmu_log("Severity 2, No response to 'query inverter id' request for inverter $serial_number");
                }
			} else {
				pmu_log("Severity 1, Inverter register acknowledgement incorrect for inverter $serial_number. Expected 06, received $register_acknowledgement");
			}
        } else {
            pmu_log("Severity 2, No response to 'send register address' request for inverter $serial_number");
        }
    } else {
        pmu_log("Severity 3, No response to 'offline query' request - no offline inverters");
    }
}

##
## Try to register known inverter
##
 
sub register_known_inverter {
              my $serial_number = shift;
        pmu_log("Severity 2: Try to register known serial number: $serial_number");
 
        # send register address (serial number followed by 1 byte address we allocate to inverter)
        $serial_num_response = pack("A*", $serial_number);
        my @register_address = unpack("C*", $serial_num_response);
        push(@register_address, $next_inverter_address);
        $address_response = send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"SEND_REGISTER_ADDRESS"}, \@register_address);
        if($address_response) {
            # check register acknowledgement
            my $len = length($address_response);
            my $register_acknowledgement = unpack("C", $address_response);
            if($register_acknowledgement == 06) {
                pmu_log("Severity 1:Inverter $serial_number acknowledged registration");
 
                # request inverter ID 
                $inverter_id_response = send_request($next_inverter_address, $CTRL_FUNC_CODES{"READ"}{"QUERY_INVERTER_ID"});
                if($inverter_id_response) {
                    my $len = length($inverter_id_response);
                    my $inverter_id = unpack("A*", $inverter_id_response);
                    pmu_log("Severity 1: Connected to inverter: $inverter_id");
 
                    # remember this inverter
                    $timestamp = get_timestamp();
                    $inverters{$next_inverter_address}{"id_string"} = $inverter_id;
                    $inverters{$next_inverter_address}{"serial"} = $serial_number;
                    $inverters{$next_inverter_address}{"connected"} = $timestamp;
                    $inverters{$next_inverter_address}{"max"} = {
                        "pac" => {
                            "watts" => 0,
                            "timestamp" => $timestamp
                        }
                    };
 
                    $next_inverter_address++;
                } else {
                    pmu_log("Severity 2: No response to 'query inverter id' request for inverter $serial_number");
                }
            } else {
                pmu_log("Severity 1: Inverter register acknowledgement incorrect for inverter $serial_number. Expected 06, received $register_acknowledgement");
            }
        } else {
            pmu_log("Severity 2: No response to 'send register address' request for inverter $serial_number");
        }
}
##
## Write a log file entry
##

sub pmu_log {
    my $msg = shift;

  (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
    my $timestamp = sprintf ("%04d-%02d-%02d %02d:%02d:%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec);

# 9th letter is the severity print substr($msg,9,1);
    if($config->options_debug >= substr($msg,9,1)) {
        print sprintf("%s: %s\n", $timestamp, $msg);
    open(OUT, ">>".$config->options_log_file) or die "Cannot open file ".$config->options_log_file." for writing\n";
    printf(OUT "%s: %s\n", $timestamp, $msg);
    close OUT;

    }
}

##
##	Validate data packet - calculate and verify checksum
##

sub validate_checksum {
	my @packet = @_;
	my $csum = 0;
	my $len = scalar(@packet);
	for($i = 0; $i < $len-2; $i++) {
		$csum += $packet[$i];
	}

   # packets with all zeroes pass checksum test, but are invalid
    return ($csum > 0)  && ($csum == (($packet[$len-2] << 8) + $packet[$len-1]));
}

##
##	Parse data packet - put two bytes together
##

sub parse_packet {
	my @packet = @_;
	my @data;
	my $j = 0;
	my $len = scalar(@packet);
	for($i = 0; $i < $len; $i+=2) {
		$data[$j++] = ($packet[$i] << 8) + $packet[($i+1)];
	}
	return @data;
}

##
##	Write out a JSON file for web server
##

sub write_web_json {
	$json_text = encode_json \%inverters;
	open(OUT, ">/tmp/eversolar") or die "Cannot open file /tmp/eversolar for writing\n";
	printf(OUT "%s", $json_text);
	close OUT;
}

##
##	Upload data to PV-log.com
##

sub upload_pvlog {

          # pv-log here
                   
   # We've accumulated data, send data to PV-log, this could be done in more detail, specs here
   #      http://photonensammler.homedns.org/wiki/doku.php?id=solarlog_datenformat#datendatei_min_dayjs


 print "uploading to pv-log\n";




}


##
##	Establish socket connection to inverter
##

sub inverter_connect {
    my $connected = 0;
    while(!$connected) {
        if($config->options_communication_method eq "eth2ser") {
            pmu_log("Severity 1, Connecting to the ethernet to serial converter");
            eth2ser_connect();
        } elsif($config->options_communication_method eq "serial") {
            pmu_log("Severity 2, Connecting to the serial port");
            serial_connect();
        }

        $next_inverter_address = START_INVERTER_ADDRESS;
		
        pmu_log("Severity 2, Asking all inverters to re-register");
		$connected = re_register_inverters();
    }

    # reset some "last" vars
    $last_min = -1;
    $e_last_wh = -1;
}

##
## get current timestamp
##

sub get_timestamp {
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
	return sprintf ("%04d-%02d-%02d %02d:%02d:%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec);
}


##
## START OF PROGRAM
##

##
## Setup sqlite database
##

$dbh->do("CREATE TABLE IF NOT EXISTS inverter (
    serial_number VARCHAR(128), 
    timestamp VARCHAR(64),
    pac INT,
    e_today FLOAT,
    e_total FLOAT,
    vpv FLOAT,
    vpv2 FLOAT,
    ipv FLOAT,
    ipv2 FLOAT,
    vac FLOAT,
    iac FLOAT,
    frequency FLOAT,
    impedance FLOAT,
    hours_up FLOAT,
    op_mode INT,
    temp FLOAT
)");

###############################################################################
##
##
##
##	Database housekeeping
##
##
##
##
##
###############################################################################
 

# vpv2 and ipv2 were added in later versions - fix any existing databases that don't have the columns
print "Update old database version, or print 2 fail messages : \n";
$dbh->do("ALTER TABLE inverter ADD COLUMN vpv2 FLOAT") or 1;
$dbh->do("ALTER TABLE inverter ADD COLUMN ipv2 FLOAT") or 1;
print "Done updating old database version.  \n";

# since version 0.16 we add a second table with daily production levels including a rolling 365 day production volume
# First we create the table, and then we populate it with historical data. This may take a little while first time around
#

	pmu_log("Severity 3, Checking database");

            my $stmt = " SELECT  COUNT(*) FROM sqlite_master WHERE type='table' AND name='daily'";
            my $sth = $dbh->prepare( $stmt );
            my $rv = $sth->execute() or die $DBI::errstr;
            my $count = $sth->fetchrow_array();

             if($count < 1){
               print $DBI::errstr;
# ok, old tadabase without the daily table. 
# create table and fill in data

  	pmu_log("Severity 1, Updating database with daily table, making data export and stats easy");

            my $stmt = " 		create table daily (
	         serial_number varchar(128) not null,
		 timestamp varchar(64) not null,
	  	 e_today float,
		 e_total float,
		 unique (serial_number, timestamp)

		)";
            my $sth = $dbh->prepare( $stmt );
            my $rv = $sth->execute() or die $DBI::errstr;

            my $stmt = " insert into daily (serial_number, timestamp, e_today,e_total)
		     select serial_number, date(timestamp),e_today, max(e_total) from inverter group by serial_number,date(timestamp) ";
            my $sth = $dbh->prepare( $stmt );
            my $rv = $sth->execute() or die $DBI::errstr;
		

             }   
###############################################################################
##
##
##
##	Web server
##
##
##
##
##
###############################################################################
 

if($config->web_server_enabled) {
#    require "web-server.pl";

	# start the web server on port $config->web_server_port
	our $web_server_pid = SolarWebServer->new($config->web_server_port)->background();

	$SIG{INT} = sub { 
		syswrite(STDERR, "\nCaught INT signal...\n");
		
		syswrite(STDERR, "Shutting down web server (pid $web_server_pid)...\n");
		my $cmd = `kill -9 $web_server_pid`;
		
		syswrite(STDERR, "Exiting.\n");
		exit;
	};

	# tmp file for web server
	$json_text = encode_json \%inverters;
	open(OUT, ">/tmp/eversolar") or die "Cannot open file /tmp/eversolar for truncating\n";
	printf(OUT "%s", $json_text);
	close OUT;
}

###############################################################################
##
##
##
##	Main Loop
##
##
##
##
##
###############################################################################
 
while(1) {
	$timestamp = get_timestamp();

        


	# connect to inverter if not connected (!$sock)
   my  $combined_power = 0;
	my  $combined_daykwh = 0;
        my $d365 =0;

		if(!$sock) {
                 inverter_connect();
                 sleep 10;
                  my $sth = $dbh->prepare("select distinct serial_number from inverter limit 10");
                  $sth->execute();
                  my $row;
                  while ($row = $sth->fetchrow_arrayref()) {
                 pmu_log("Severity 2: got serial @$row[0] from database");
                 register_known_inverter( @$row[0]);
                 sleep 10;

                      }

                  $sth->finish();
               }
	
#aggresive polling when no inverters connected
		while(keys(%inverters)==0) {
                 register_inverter();
               }



	$timestamp = get_timestamp();

	# see if there are any new inverters every once in a while (every minute)
	if($min != $last_min) {
		pmu_log("Severity 2, Asking for any inverters to register");
		register_inverter();
	      }
	# request data from each connected inverter
         $combined_power = 0;
         $combined_daykwh = 0;
	foreach $inverter (keys(%inverters)) {
		$response = send_request($inverter, $CTRL_FUNC_CODES{"READ"}{"QUERY_NORMAL_INFO"});
        if($response) {
            # good response - reset response_timeout_count
            $inverters{$inverter}{"response_timeout_count"} = 0;

            my $len = length($response);
            my @data = parse_packet(unpack("C$len", $response));
            
            my $e_today_kwh = $data[$DATA_BYTES{'E_TODAY'}]/100;
            my $e_today_wh = $e_today_kwh * 1000;
            my $e_total = $data[$DATA_BYTES{'E_TOTAL'}]/10 +$data[$DATA_BYTES{'NA_1'}]*65535/10; # NA_1 is actually upper bytes of total production
            my $pac = $data[$DATA_BYTES{'PAC'}];
            if ($data[$DATA_BYTES{'TEMP'}]>=0x8000) {$data[$DATA_BYTES{'TEMP'}]-=0x10000;}  # Temperature is signed, -0.1 = 0xFFFF
            my $temp = $data[$DATA_BYTES{'TEMP'}]/10;
            my $volts = $data[$DATA_BYTES{'VAC'}]/10;

            $combined_power = $combined_power +$data[$DATA_BYTES{'PAC'}];
            $combined_daykwh = $combined_daykwh +$data[$DATA_BYTES{'E_TODAY'}]/100;

            $d365 = $e_total ;
 # store in db
print "select min(e_total) as mins from inverter where timestamp  >=   date('now', '-1 year') and serial_number = ".$inverters{$inverter}{"serial"};

            my $stmt = "select min(e_total) as mins from inverter where timestamp  >=   date('now', '-365 day') and serial_number = '".$inverters{$inverter}{"serial"}."'";
            my $sth = $dbh->prepare( $stmt );
            my $rv = $sth->execute() or die $DBI::errstr;
             if($rv < 0){
               print $DBI::errstr;
             }
            while(my @row = $sth->fetchrow_array()) {
                            print "etot = ". $row[0] . "\n";
            $d365 = $e_total-$row[0] ;
                }
print "Operation done successfully\n";

            pmu_log("Severity 3, ".$inverters{$inverter}{"serial"}." output: $pac W, Total: $e_total kWh, Today: $e_today_kwh kWh, 365 days : $d365 ");
 # store in db

						
            $inverters{$inverter}{"data"} = {
                "timestamp" 	=> $timestamp,
                "pac" 		=> $data[$DATA_BYTES{'PAC'}],
                "e_today" 	=> $e_today_kwh,
                "e_total" 	=> $e_total,
                "vpv" 		=> $data[$DATA_BYTES{'VPV'}]/10,
                "vpv2" 		=> $data[$DATA_BYTES{'VPV2'}]/10,
                "ipv" 		=> $data[$DATA_BYTES{'IPV'}]/10,
                "ipv2" 		=> $data[$DATA_BYTES{'IPV2'}]/10,
                "vac" 		=> $data[$DATA_BYTES{'VAC'}]/10,
                "iac" 		=> $data[$DATA_BYTES{'IAC'}]/10,
                "frequency" 	=> $data[$DATA_BYTES{'FREQUENCY'}]/100,
                "d365" 	        => $d365,
                "impedance" 	=> $data[$DATA_BYTES{'IMPEDANCE'}],
                "hours_up" 	=> $data[$DATA_BYTES{'HOURS_UP'}],
                "op_mode" 	=> $data[$DATA_BYTES{'OP_MODE'}],
                "temp"	 	=> $temp,
                "total_power"	=> $combined_power,
                "total_daykwh"	=> $combined_daykwh 
            };

            # store in db
            $dbh->do("
                INSERT INTO inverter 
                    (serial_number, 
                     timestamp, 
                     pac, 
                     e_today, 
                     e_total, 
                     vpv, 
                     vpv2, 
                     ipv, 
                     ipv2, 
                     vac, 
                     iac, 
                     frequency, 
                     impedance, 
                     hours_up, 
                     op_mode, 
                     temp) 
                VALUES 
                    ('".$inverters{$inverter}{"serial"}."',
                     '".$inverters{$inverter}{"data"}{"timestamp"}."',
                     '".$inverters{$inverter}{"data"}{"pac"}."',
                     '".$inverters{$inverter}{"data"}{"e_today"}."',
                     '".$inverters{$inverter}{"data"}{"e_total"}."',
                     '".$inverters{$inverter}{"data"}{"vpv"}."',
                     '".$inverters{$inverter}{"data"}{"vpv2"}."',
                     '".$inverters{$inverter}{"data"}{"ipv"}."',
                     '".$inverters{$inverter}{"data"}{"ipv2"}."',
                     '".$inverters{$inverter}{"data"}{"vac"}."',
                     '".$inverters{$inverter}{"data"}{"iac"}."',
                     '".$inverters{$inverter}{"data"}{"frequency"}."',
                     '".$inverters{$inverter}{"data"}{"impedance"}."',
                     '".$inverters{$inverter}{"data"}{"hours_up"}."',
                     '".$inverters{$inverter}{"data"}{"op_mode"}."',
                     '".$inverters{$inverter}{"data"}{"temp"}."'
                    )
            ");

            if($data[$DATA_BYTES{'PAC'}] > $inverters{$inverter}{"max"}{"pac"}{"watts"}) {
                $inverters{$inverter}{"max"}{"pac"} = {
                    "timestamp"	=> $timestamp,
                    "watts"		=> $data[$DATA_BYTES{'PAC'}]
                };
            }

            # tmp file for web server
            if($config->web_server_enabled) {
                write_web_json();
            }


            ###############################################################################
            ##
            ##
            ##
            ##	Data to PVoutput.org
            ##
            ##
            ##
            ###############################################################################


            if($config->pvoutput_enabled && ($min % $config->pvoutput_status_interval_mins) == 0 && $min != $last_min) {
                my $pv_date = `date +%Y%m%d`;
                my $pv_time = `date +%H:%M`;
                chomp($pv_date);
                chomp($pv_time);

                my $pvoutput_api_key = $config->pvoutput_api_key;
                my $pvoutput_add_status_url = $config->pvoutput_add_status_url;
                my $this_pvoutput_system_id = $config->pvoutput_system_id->{$inverters{$inverter}{"serial"}};
              #use Data::Dumper;
              #print Dumper($this_pvoutput_system_id);
              #die;

                my $cmd = `curl -m 30 -s -d "d=$pv_date" -d "t=$pv_time" -d "v1=$e_today_wh" -d "v2=$pac" -d "v5=$temp" -d "v6=$volts" -H "X-Pvoutput-Apikey:$pvoutput_api_key" -H "X-Pvoutput-SystemId:$this_pvoutput_system_id" $pvoutput_add_status_url 2>&1 `;                chomp($cmd);
                pmu_log("Severity 3, ".$inverters{$inverter}{"serial"}." uploading to pvoutput.org, response: $cmd");

            }
            ###############################################################################
            ##
            ##
            ##
            ##	Data to domoticz
            ##
            ##
            ##
            ###############################################################################


        if($config->domoticz_enabled) {

            my $domoticz_address = $config->domoticz_address;
            my $domoticz_port = $config->domoticz_port;
            my $domoticz_IDX = $config->domoticz_IDX;

            my $cmd = `curl -s "http://$domoticz_address:$domoticz_port/json.htm?type=command&param=udevice&idx=$domoticz_IDX&nvalue=0&svalue=$pac;$e_today_wh" `;
	chomp($cmd);
            pmu_log("Severity 3, ".$inverters{$inverter}{"serial"}." uploading to domoticz, response: $cmd");

        }
            ###############################################################################
            ##
            ##
            ##
            ##	Data to seg
            ##
            ##
            ##
            ###############################################################################

            # send data to seg
            if($config->seg_enabled && ($min % $config->seg_upload_interval_mins) == 0 && $min != $last_min) {
                if($e_last_wh >= 0) { #first iteration, cant upload to seg yet
                    my $e_now_wh = $e_today_wh - $e_last_wh;
            
                    my $seg_site_id = $config->seg_site_id;
                    my $seg_device = $config->seg_device;
                    my $seg_power_stream = $config->seg_power_stream;
                    my $seg_energy_stream = $config->seg_energy_stream;
                    my $seg_api_url = $config->seg_api_url;

                    $curl_data = "(node $seg_device ? ($seg_power_stream $pac) ($seg_energy_stream $e_now_wh))";
                    my $cmd = `curl -s -d "data_post=(site $seg_site_id $curl_data)" $seg_api_url 2>&1 `;
                    chomp($cmd);
                    pmu_log("Severity 3, ".$inverters{$inverter}{"serial"}." uploading to smartenergygroups.com (power: $pac, energy: $e_now_wh), response: $cmd");
                }


                $e_last_wh = $e_today_wh;
               }

            ###############################################################################
            ##
            ##
            ##
            ##	Data to pv-log 
            ##
            ##
            ##
            ###############################################################################

                   
            if($config->pvlog_enabled && ($min % $config->pvlog_interval == 0 && $min != $pvlog_last_min)) {
                    # $pvlog_last_min is used to only update once per minute. IUn case of multiple inverters we would create a line per inverter in the js file.
                    $pvlog_last_min = $min;

          # Send data to PV-log, this could be done in more detail, specs here
          #      http://photonensammler.homedns.org/wiki/doku.php?id=solarlog_datenformat#datendatei_min_dayjs


                     # export min_day.js file


		      #  encoding = datetime | PAC in W | PDC in W| daily production up to now in Wh| UDC in V	

                      # Anlage mit zwei WR, 1.WR 3 Strings, 2.WR keine Strings mit WR Innentemperatur:
                      #   m[mi++]=?07.05.12 15:15:00|904;372;346;376;16656;403;406;404|495;532;9234;321;55?
                      #   m[mi++]=?07.05.12 15:10:00|1000;403;376;408;16581;397;406;400|544;582;9192;321;52?
                      #   m[mi++]=?07.05.12 15:05:00|1088;435;408;439;16500;399;400;397|587;628;9147;321;53?
                      # m[mi++]=?07.05.12 15:10:00	 |	 1000	 ;	 403	 ;	 376	 ;	 408	 ;	 16581	 ;	 397	 ;	 406	 ;	 400	 |	 544	 ;	 582	 ;	 9192	 ;	 321	 ;	 52	 ?
                      # Kennung, Datum, Uhrzeit | PAC WR 1 in W| PDC String 1 WR 1 in W | PDC String 2 WR 1 in W| PDC String 3 WR 1 in W		 Tages-
                      # ertrag WR 1 in Wh		 UDC String 1 WR 1 in V		 UDC String 2 WR 1 in V		 UDC String 3 WR 1 in V		 PAC WR 2 in W		 PDC WR 2 in W		 Tages-
                      # ertrag WR 2 in Wh		 UDC WR 2 in V		 Tempe-
                      # ratur WR 2 in °C	

                      # So the 2 inverters basically share format, they are just divided by a simple |

                      # Initialize string
                    our  $update= sprintf("m\[mi++\]\=\"%02d.%02d.%02d %02d:%02d:00",$mday,$mon+1,$year-100,$hour,$min);
                      

     
                      # For each inverter, add the inverters data to the string
                      # The format is different between one and two stringed ingerters though

                       foreach $inverter (sort (keys(%inverters))) {
                         if($config->options_strings == 1) {
                             my $pdc1 = $inverters{$inverter}{"data"}{"ipv"}*$inverters{$inverter}{"data"}{"vpv"};
                             $update= $update . sprintf("|%d;%d;%d;%d;%d",$inverters{$inverter}{"data"}{"pac"}, $pdc1,$inverters{$inverter}{"data"}{"e_today"}*1000,$inverters{$inverter}{"data"}{"vpv"},$inverters{$inverter}{"data"}{"temp"});
                            }else
                            { # two strings
                             my $pdc1 = $inverters{$inverter}{"data"}{"ipv"}*$inverters{$inverter}{"data"}{"vpv"};
                             my $pdc2 = $inverters{$inverter}{"data"}{"ipv2"}*$inverters{$inverter}{"data"}{"vpv2"};
                             $update= $update . sprintf("|%d;%d;%d;%d;%d;%d;%d",$inverters{$inverter}{"data"}{"pac"}, $pdc1,$pdc2,$inverters{$inverter}{"data"}{"e_today"}*1000,$inverters{$inverter}{"data"}{"vpv"},$inverters{$inverter}{"data"}{"vpv2"},$inverters{$inverter}{"data"}{"temp"});
                            
                            }


        
                       }

                      # other available data is:     
                      #                      '".$inverters{$inverter}{"data"}{"timestamp"}."',
                      #                      '".$inverters{$inverter}{"data"}{"pac"}."',
                      #                      '".$inverters{$inverter}{"data"}{"e_today"}."',
                      #                      '".$inverters{$inverter}{"data"}{"e_total"}."',
                      #                      '".$inverters{$inverter}{"data"}{"vpv"}."',
                      #                      '".$inverters{$inverter}{"data"}{"vpv2"}."',
                      #                      '".$inverters{$inverter}{"data"}{"ipv"}."',
                      #                      '".$inverters{$inverter}{"data"}{"ipv2"}."',
                      #                      '".$inverters{$inverter}{"data"}{"vac"}."',
                      #                      '".$inverters{$inverter}{"data"}{"iac"}."',
                      #                      '".$inverters{$inverter}{"data"}{"frequency"}."',
                      #                      '".$inverters{$inverter}{"data"}{"impedance"}."',
                      #                      '".$inverters{$inverter}{"data"}{"hours_up"}."',
                      #                      '".$inverters{$inverter}{"data"}{"op_mode"}."',
                      #                      '".$inverters{$inverter}{"data"}{"temp"}."'

			 # now finalize the string
                      $update= $update . sprintf("\"\n");

                     # debug     print   $update;

			 # write the string to the js file

                      pmu_log("Severity 3, uploading to pv-log.com, data: $update");

                     unless (-e 'min_day.js')
                       {
                        open (MYFILE, '>>min_day.js');
                        print MYFILE $update;
                        close (MYFILE);      
                       }
                       else
                       {
                        open my $in,  '<',  'min_day.js'      or die "Can't read old file: $!";
                        open my $out, '>', 'pvlogtemp' or die "Can't write new file: $!";

                         print $out $update; # <--- HERE'S THE MAGIC

                        while( <$in> ) {
                         print $out $_;
                         }

                             close $out; 
                             copy('pvlogtemp','min_day.js');
                        }

                     
                    
                     # FTP file to pv-log
                     # upload the file
                         
                      eval {
                            $ftp = Net::FTP->new($config->pvlog_FTPServeradresse, Debug => 0)
                             or  warn "Cannot connect to some.host.name: $@";
                            $ftp->login($config->pvlog_username,$config->pvlog_Password)
                             or warn "Cannot login ", $ftp->message;
                            $ftp->put("min_day.js")
                             or warn "put failed ", $ftp->message;
                            $ftp->quit;
                        }

               }



        } else {
            $inverters{$inverter}{"response_timeout_count"}++;
            pmu_log("Severity 2, ".$inverters{$inverter}{"serial"}." lost contact with inverter (".$inverters{$inverter}{"response_timeout_count"}." time(s))");

            if($inverters{$inverter}{"response_timeout_count"} == 3) {
                pmu_log("Severity 1, ".$inverters{$inverter}{"serial"}." lost contact with inverter, forgetting inverter");
                # forget about the inverter
                delete $inverters{$inverter};

                # Remember to delete pv-log upload file here
                 if($config->pvoutput_enabled && keys(%inverters)==0)
			{
                            if (-e 'min_day.js') {
                              print "cleaning up after pvlog - deleting min_day.js file";
                              unlink ('min_day.js');
                              unlink ('pvlogtemp');
                                } 
			}

                # Delete the log file monthly to prevent the solution from filling the disk
                # this also keeps the web page responsive
                 if($mday==1 && keys(%inverters)==0 && $hour ==1)
                   {
                       unlink ($config->options_log_file);


                   }
# Old version deleted webfile at the end of day - request to keep it so it's possible to read what was produced after shutdown
#                if($config->web_server_enabled) {
#                    write_web_json();
#                }

                # force a reconnect to the inverter(s) - there may be no online inverter(s) now
                # $sock = 0;
            }

            # break out of foreach($inverters... and go to start of main loop
            last;
        }
#            pmu_log("Severity 3, ".$inverters{$inverter}{"serial"}." Total kWh_: $inverters{$inverter}{"data"}{"e_total"} kWh, Today: $e_today_kwh kWh");


    }


	$last_min = $min;

	sleep $config->options_query_inverter_secs;
	
}

pmu_log("Severity 1, Main loop ended - about to exit - why?");

if($config->options_communication_method eq "eth2ser") {
	close $sock;
} elsif($config->options_communication_method eq "serial") {
	$sock->close;
}
