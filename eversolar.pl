#! /usr/bin/perl
#
# Eversolar inverter data logger
# - Based on Steve Cliffe's <steve@sjcnet.id.au> Eversolar PMU logger script (http://www.sjcnet.id.au/computers/eversolar-inverter-monitoring-with-linux)
# - Tested and known to work with the following inverters:
# -- TL1500AS Inverter connected to an ethernet to serial converter
# -- TL2000 (multiple) connected to a Raspberry Pi
# -- TL3000 (multiple) connected to a Raspberry Pi
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
#    - added temp and volts (PV) to pvoutput.org upload
# Code move to http://code.google.com/p/eversolar-monitor/ - August 31 2012
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
$config->define("seg_enabled=s");
$config->define("seg_upload_interval_mins=s");
$config->define("seg_site_id=s");
$config->define("seg_device=s");
$config->define("seg_power_stream=s");
$config->define("seg_energy_stream=s");
$config->define("seg_api_url=s");
$config->define("web_server_enabled=s");
$config->define("web_server_port=s");
$config->file("eversolar.ini");

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
        "NA_1"		=> 11,
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
our $e_last_wh = -1;

our $next_inverter_address = START_INVERTER_ADDRESS;
our %inverters;

our $dbh = DBI->connect("dbi:SQLite:db.sqlite");

##
## sub routines
##

##
## send packet to inverter
##

sub send_request {
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
			pmu_log("Failed to write to socket: $!");
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
            #    pmu_log("Failed to read from socket: $!");
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
			pmu_log("Connected to the ethernet to serial converter");
		} else {
			pmu_log("Unable to connect to the ethernet to serial converter ... sleeping 60 seconds");
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
## send the re-register packet to inverters 3 times (happens after initial connect)
##

sub re_register_inverters {
	# ask all inverters to drop their registration and respond to register requests - send packet 3 times as per protocol specs
    for(my $i=0; $i<3; $i++) {
	    unless(send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"RE_REGISTER"})) {
            pmu_log("Failed to send re-register message");
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
	if($serial_num_response) {
		my $serial_number = unpack("A*", $serial_num_response);
		pmu_log("Found serial number: $serial_number");

		# send register address (serial number followed by 1 byte address we allocate to inverter)
		my @register_address = unpack("C*", $serial_num_response);
		push(@register_address, $next_inverter_address);
		$address_response = send_request(0x00, $CTRL_FUNC_CODES{"REGISTER"}{"SEND_REGISTER_ADDRESS"}, \@register_address);
		if($address_response) {
			# check register acknowledgement
    		my $len = length($address_response);
			my $register_acknowledgement = unpack("C", $address_response);
			if($register_acknowledgement == 06) {
				pmu_log("Inverter acknowledged registration");

				# request inverter ID 
				$inverter_id_response = send_request($next_inverter_address, $CTRL_FUNC_CODES{"READ"}{"QUERY_INVERTER_ID"});
				if($inverter_id_response) {
				    my $len = length($inverter_id_response);
					my $inverter_id = unpack("A*", $inverter_id_response);
					pmu_log("Connected to inverter: $inverter_id");

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
                    pmu_log("No response to 'query inverter id' request for inverter $serial_number");
                }
			} else {
				pmu_log("Inverter register acknowledgement incorrect for inverter $serial_number. Expected 06, received $register_acknowledgement");
			}
        } else {
            pmu_log("No response to 'send register address' request for inverter $serial_number");
        }
    } else {
        pmu_log("No response to 'offline query' request - no offline inverters");
    }
}


##
## Write a log file entry
##

sub pmu_log {
    my $msg = shift;

    $timestamp = get_timestamp();

    open(OUT, ">>".$config->options_log_file) or die "Cannot open file ".$config->options_log_file." for writing\n";
    printf(OUT "%s: %s\n", $timestamp, $msg);
    close OUT;

    if($config->options_debug) {
        print sprintf("%s: %s\n", $timestamp, $msg);
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

	return $csum == (($packet[$len-2] << 8) + $packet[$len-1]);
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
##	Establish socket connection to inverter
##

sub inverter_connect {
    my $connected = 0;
    while(!$connected) {
        if($config->options_communication_method eq "eth2ser") {
            pmu_log("Connecting to the ethernet to serial converter");
            eth2ser_connect();
        } elsif($config->options_communication_method eq "serial") {
            pmu_log("Connecting to the serial port");
            serial_connect();
        }

        $next_inverter_address = START_INVERTER_ADDRESS;
		
        pmu_log("Asking all inverters to re-register");
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

# vpv2 and ipv2 were added in later versions - fix any existing databases that don't have the columns
$dbh->do("ALTER TABLE inverter ADD COLUMN vpv2 FLOAT") or 1;
$dbh->do("ALTER TABLE inverter ADD COLUMN ipv2 FLOAT") or 1;


##
## web server
##

if($config->web_server_enabled) {
    require "web-server.pl";

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

##
##	Main Loop
##

while(1) {
	# connect to inverter if not connected (!$sock)
    if(!$sock) {
        inverter_connect();
    }
	
	$timestamp = get_timestamp();

	# see if there are any new inverters every once in a while (every minute)
	if($min != $last_min) {
		pmu_log("Asking for any inverters to register");
		register_inverter();
	}

	# request data from each connected inverter
	foreach $inverter (keys(%inverters)) {
		$response = send_request($inverter, $CTRL_FUNC_CODES{"READ"}{"QUERY_NORMAL_INFO"});

        if($response) {
            # good response - reset response_timeout_count
            $inverters{$inverter}{"response_timeout_count"} = 0;

            my $len = length($response);
            my @data = parse_packet(unpack("C$len", $response));
            
            my $e_today_kwh = $data[$DATA_BYTES{'E_TODAY'}]/100;
            my $e_today_wh = $e_today_kwh * 1000;
            my $e_total = $data[$DATA_BYTES{'E_TOTAL'}]/10;
            my $pac = $data[$DATA_BYTES{'PAC'}];
            my $temp = $data[$DATA_BYTES{'TEMP'}]/10;
            my $volts = $data[$DATA_BYTES{'VAC'}]/10;

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
                "impedance" 	=> $data[$DATA_BYTES{'IMPEDANCE'}],
                "hours_up" 	=> $data[$DATA_BYTES{'HOURS_UP'}],
                "op_mode" 	=> $data[$DATA_BYTES{'OP_MODE'}],
                "temp"	 	=> $data[$DATA_BYTES{'TEMP'}]/10
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

            if($data[PAC] > $inverters{$inverter}{"max"}{"pac"}{"watts"}) {
                $inverters{$inverter}{"max"}{"pac"} = {
                    "timestamp"	=> $timestamp,
                    "watts"		=> $data[$DATA_BYTES{'PAC'}]
                };
            }

            # tmp file for web server
            if($config->web_server_enabled) {
                write_web_json();
            }

            pmu_log($inverters{$inverter}{"serial"}." output: $pac W, Total: $e_total kWh, Today: $e_today_kwh kWh");

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

                my $cmd = `curl -m 30 -s -d "d=$pv_date" -d "t=$pv_time" -d "v1=$e_today_wh" -d "v2=$pac" -d "v5=$temp" -d "v6=$volts" -H "X-Pvoutput-Apikey:$pvoutput_api_key" -H "X-Pvoutput-SystemId:$this_pvoutput_system_id" $pvoutput_add_status_url 2>&1 `;
                chomp($cmd);
                pmu_log($inverters{$inverter}{"serial"}." uploading to pvoutput.org, response: $cmd");

            }

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
                    pmu_log($inverters{$inverter}{"serial"}." uploading to smartenergygroups.com (power: $pac, energy: $e_now_wh), response: $cmd");
                }

                $e_last_wh = $e_today_wh;
            }
        } else {
            $inverters{$inverter}{"response_timeout_count"}++;
            pmu_log($inverters{$inverter}{"serial"}." lost contact with inverter (".$inverters{$inverter}{"response_timeout_count"}." time(s))");

            if($inverters{$inverter}{"response_timeout_count"} == 1) {
                pmu_log($inverters{$inverter}{"serial"}." lost contact with inverter, forgetting inverter");
                # forget about the inverter
                delete $inverters{$inverter};

                if($config->web_server_enabled) {
                    write_web_json();
                }

                # force a reconnect to the inverter(s) - there may be no online inverter(s) now
                # $sock = 0;
            }

            # break out of foreach($inverters... and go to start of main loop
            last;
        }
    }

	$last_min = $min;

	sleep $config->options_query_inverter_secs;
	
}

pmu_log("Main loop ended - about to exit - why?");

if($config->options_communication_method eq "eth2ser") {
	close $sock;
} elsif($config->options_communication_method eq "serial") {
	$sock->close;
}

