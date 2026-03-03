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

use AppConfig;
use Time::HiRes;        # Used for timestamp precision
use JSON;               # Used by MQTT command response
use POSIX qw(strftime); # Used for timestamp formatting in MQTT
use File::Copy;
use POSIX;
use utf8;
use AnyEvent;
use AnyEvent::MQTT;

#use warnings;

our $config = AppConfig->new();

# Basic and required settings
$config->define("configFile=s");
$config->define("options_debug=s");
$config->define("options_query_inverter_secs=s");
$config->define("options_log_file=s");
$config->define("options_output_to_log=s");
$config->define("options_clean_log=s");
$config->define("options_communication_method=s");
$config->define("options_strings=s");
$config->define("options_power_limit_refresh_mins=s");

# Connection method: SERIAL only in this case - add eth2ser if needed.
$config->define("serial_port=s");

# MQTT (Home Assistant) config
$config->define("mqtt_enabled=s");
$config->define("mqtt_inverter_model=s");               
$config->define("mqtt_host=s");
$config->define("mqtt_port=s");
$config->define("mqtt_enable_pass=s");
$config->define("mqtt_user=s");
$config->define("mqtt_password=s");
$config->define("mqtt_topic_prefix=s");
$config->define("mqtt_ha_discovery=s");
$config->define("mqtt_command_topic=s");
$config->define("mqtt_response_topic=s");


# MQTT listening features
our $mqtt_limit_command;            # shared variable to hold latest power limit request
our $mqtt;                          # the MQTT client object
our $last_power_limit = 99;        # Power limit variable to use for when inverter is registered - #### test 99% to avoid cancelling active power function
our $sleep_time_cnt = 0;            # Counter for sleep time when no inverters are registered


#$config->file("eversolar.ini");

$config->define("configFile=s");                # Define a config file parameter
$config->args();                                # Parse the command line arguments

if ( $config->configFile eq '' ) {
    $config->configFile('eversolar.ini');
}

-e $config->configFile or die "Configfile '", $config->configFile, "' not found\n";

$config->file( $config->configFile );
pmu_log( "Severity 1, Configfile is: " . $config->configFile );

# Ensure that MQTT listener is enabled if enabled in eversolar.ini
if ($config->mqtt_enabled && $config->mqtt_enabled == 1) {
    init_mqtt_command_listener();
}

# Control codes and function codes
%CTRL_FUNC_CODES = (
    "REGISTER" => {    # CONTROL CODE 0x10
        "OFFLINE_QUERY" => {
            "REQUEST"  => [ 0x10, 0x00 ],
            "RESPONSE" => [ 0x10, 0x80 ]
        },
        "SEND_REGISTER_ADDRESS" => {
            "REQUEST"  => [ 0x10, 0x01 ],
            "RESPONSE" => [ 0x10, 0x81 ]
        },
        "RE_REGISTER" => {
            "REQUEST"  => [ 0x10, 0x04 ],
            "RESPONSE" => ""
        }
    },
    "READ" => {    # CONTROL CODE 0x11
        "QUERY_INVERTER_ID" => {
            "REQUEST"  => [ 0x11, 0x03 ],
            "RESPONSE" => [ 0x11, 0x83 ]
        },
        "QUERY_NORMAL_INFO" => {
            "REQUEST"  => [ 0x11, 0x02 ],
            "RESPONSE" => [ 0x11, 0x82 ]
        },
        "QUERY_DESCRIPTION" => {
            "REQUEST"  => [ 0x11, 0x00 ],
            "RESPONSE" => [ 0x11, 0x80 ]
        },
    },
    "WRITE" => {    # CONTROL CODE 0x12
    },
    "EXECUTE" => {    # CONTROL CODE 0x13
        "LIMIT_POWER" => {  
            "REQUEST"  => [ 0x13, 0x20 ],
            "RESPONSE" => ""
        },
    }
);

if ( $config->options_strings == 1 ) {
    %DATA_BYTES = (
        "TEMP"      => 0,
        "E_TODAY"   => 1,
        "VPV"       => 2,
        "IPV"       => 3,
        "IAC"       => 4,
        "VAC"       => 5,
        "FREQUENCY" => 6,
        "PAC"       => 7,
        "IMPEDANCE" => 8,
        "NA_1"      => 9,
        "E_TOTAL"   => 10,
        "NA_2"      => 11,
        "HOURS_UP"  => 12,
        "OP_MODE"   => 13
    );
}
elsif ( $config->options_strings == 2 ) {
    %DATA_BYTES = (
        "TEMP"      => 0,
        "E_TODAY"   => 1,
        "VPV"       => 2,
        "VPV2"      => 3,
        "IPV"       => 4,
        "IPV2"      => 5,
        "IAC"       => 6,
        "VAC"       => 7,
        "FREQUENCY" => 8,
        "PAC"       => 9,
        "NA_0"      => 10,
        "NA_1"      => 11,    # NA_1 is actually upper bytes of total production
        "E_TOTAL"   => 12,
        "NA_2"      => 13,
        "HOURS_UP"  => 14,
        "OP_MODE"   => 15
    );
}
else {
    die "Incorrect config option for 'strings'\n";
}

use constant START_INVERTER_ADDRESS => 0x10;    # start at 10 - giving us 244 available addresses
use constant OUR_ADDRESS            => 0x01;

our $sock           = 0;
our $last_min       = -1;
our $pvlog_last_min = -1;
our $e_last_wh      = -1;

our $next_inverter_address = START_INVERTER_ADDRESS;
our %inverters;

##
## sub routines
##

##
## send packet to inverter
##

sub send_request {

    # Don't send if not connected
    if ( !$sock ) {
        pmu_log("Severity 3, Socket not present for sending");
        return 0
    }

    my $destination_address = shift;
    my ( $ctrl_func_code, $data ) = @_;
    %ctrl_func_code = %$ctrl_func_code;
    @data           = @$data;

    my $data_length = scalar(@data);

    @tmp_packet = ( 0xAA, 0x55, OUR_ADDRESS, 0x00, 0x00, $destination_address, $ctrl_func_code{"REQUEST"}[0], $ctrl_func_code{"REQUEST"}[1], $data_length );
    if ($data_length) {
        push( @tmp_packet, @data );
    }

    $tmp_packet_length = scalar(@tmp_packet);

    # calculate checksum
    my $checksum = 0;
    for ( $i = 0 ; $i < $tmp_packet_length ; $i++ ) {
        $checksum += $tmp_packet[$i];
    }

    $packet = pack( "C" . $tmp_packet_length . "n", ( @tmp_packet, $checksum ) );

    if ( $config->options_debug >= 4 ) {    
        print "sending packet to inverter... \n";
        print_bytes( $packet, length($packet) );
    }

    if ( $config->options_communication_method eq "serial" ) {
        $sock->write($packet);
    }

    # allow time for inverter to respond
    sleep 1;

    if ( $ctrl_func_code{"RESPONSE"} ne "" ) {
        if ( $config->options_communication_method eq "serial" ) {
            ( $count_in, $response ) = $sock->read(256);
        }

        if ( length($response) ) {
            @recv_packet = unpack( "C*", $response );

            if ( $config->options_debug >= 4 ) {    
                print "received packet from inverter: \n";
                print_bytes( $response, length($response) );
            }

            if ( validate_checksum(@recv_packet) ) {
                my $len = length($response) - 11;
                my ( $ctrl_code, $func_code, @data ) = unpack( "xxxxxxCCxC" . $len . "xx", $response );

                #use Data::Dumper;
                #print Dumper(\@data);

                if (   $ctrl_code == $ctrl_func_code{"RESPONSE"}[0]
                    && $func_code == $ctrl_func_code{"RESPONSE"}[1] )
                {
                    return pack( "C*", @data );
                }
            }
        }
    }
    else {
        return 1;
    }

    # if we fall through to here, something isn't right!
    pmu_log("Severity 3, fallback to no response");
    return 0;
}

##
## Dump a buffer in hex for debugging purposes
##

sub print_bytes {
    my $buf        = shift;
    my $len        = shift;
    my $line_count = 0;

    if ( $len <= 0 ) {
        return;
    }

    my @bytes = unpack( "C$len", $buf );

    if ( $len > 0 ) {
        for ( my $i = 0 ; $i < $len ; $i++ ) {
            printf "%02x ", $bytes[$i];
            if ( $line_count++ > 15 ) {
                $line_count = 0;
                print "\n";
            }
        }
    }
    printf "\n";
}

##
## Connect directly to the inverter via serial
##

sub serial_connect {
    if ( $^O eq 'MSWin32' ) {    # Win32 (ActivePerl)
        eval "use Win32::SerialPort";
        $sock = Win32::SerialPort->new( $config->serial_port, 0, '' ) || die "Can\'t open $port: $!";
    }
    else {                       # Unix/Linux/other
        eval "use Device::SerialPort";
        $sock = Device::SerialPort->new( $config->serial_port, 0, '' ) || die "Can\'t open $port: $!";
    }

    $sock->baudrate(9600)    || die 'fail setting baudrate, try -b option';
    $sock->parity("none")    || die 'fail setting parity';
    $sock->databits(8)       || die 'fail setting databits';
    $sock->stopbits(1)       || die 'fail setting stopbits';
    $sock->handshake("none") || die 'fail setting handshake';
    $sock->datatype("raw")   || die 'fail setting datatype';
    $sock->write_settings    || die 'could not write settings';
    $sock->read_char_time(0);        # don't wait for each character
    $sock->read_const_time(1000);    # 1 second per unfulfilled "read" call
}

##
## send the re-register packet to inverters 8 times (happens after initial connect)
##

sub re_register_inverters {

    # ask all inverters to drop their registration and respond to register requests - send packet 3 times as per protocol specs
    for ( my $i = 0 ; $i < 8 ; $i++ ) {
        unless ( send_request( 0x00, $CTRL_FUNC_CODES{"REGISTER"}{"RE_REGISTER"} ) ) {
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
    $serial_num_response = send_request( 0x00, $CTRL_FUNC_CODES{"REGISTER"}{"OFFLINE_QUERY"} );
    if ($serial_num_response) {    ##bugfix september 2nd 2015 for serial numbers containing null: Z* instead of A*:
        my $serial_number = unpack( "Z*", $serial_num_response );
        pmu_log("Severity 3, Unpacked received serial number: $serial_number .");
        $serial_number =~ s/\W//g;
        pmu_log("Severity 1, Cleaned received serial number: $serial_number .");
        
        # send register address (serial number followed by 1 byte address we allocate to inverter)
        my @register_address = unpack( "C*", $serial_num_response );
        push( @register_address, $next_inverter_address );
        $address_response =
          send_request( 0x00, $CTRL_FUNC_CODES{"REGISTER"}{"SEND_REGISTER_ADDRESS"}, \@register_address );
        if ($address_response) {

            # check register acknowledgement
            my $len                      = length($address_response);
            my $register_acknowledgement = unpack( "C", $address_response );
            if ( $register_acknowledgement == 06 ) {
                pmu_log("Severity 1, Inverter acknowledged registration");

                # request inverter ID
                $inverter_id_response =
                  send_request( $next_inverter_address, $CTRL_FUNC_CODES{"READ"}{"QUERY_INVERTER_ID"} );
                if ($inverter_id_response) {
                    my $len         = length($inverter_id_response);
                    my $inverter_id = unpack( "A*", $inverter_id_response );
                    pmu_log("Severity 1, Connected to inverter: $inverter_id");

                    # remember this inverter
                    $timestamp                                      = get_timestamp();
                    $inverters{$next_inverter_address}{"id_string"} = $inverter_id;
                    $inverters{$next_inverter_address}{"serial"}    = $serial_number;
                    $inverters{$next_inverter_address}{"connected"} = $timestamp;
                    $inverters{$next_inverter_address}{"max"}       = {
                        "pac" => {
                            "watts"     => 0,
                            "timestamp" => $timestamp
                        }
                    };
                    $inverters{$next_inverter_address}{"daily_retrieved"} = 0;
#                    set_power_limit($next_inverter_address, 99, 30);                   #Ensure that the inverter is set at a power limit of 100% at, ramp up time is 30s  (test 99%)
                    $inverters{$next_inverter_address}{"daily_retrieved_value"} = 0;
                    $inverters{$next_inverter_address}{"daily_stored"} = 0;
                    
                    # If an MQTT power limit command was retained, apply it now
                    if (defined $mqtt_limit_command) {
                        set_power_limit($next_inverter_address, $mqtt_limit_command, 10);
                        pmu_log("Severity 1, MQTT power limit $mqtt_limit_command% applied to newly registered inverter");
                    }


                    $next_inverter_address++;
                }
                else {
                    pmu_log("Severity 2, No response to 'query inverter id' request for inverter $serial_number");
                }
            }
            else {
                pmu_log("Severity 1, Inverter register acknowledgement incorrect for inverter $serial_number. Expected 06, received $register_acknowledgement");
            }
        }
        else {
            pmu_log("Severity 2, No response to 'send register address' request for inverter $serial_number");
        }
    }
    else {
        pmu_log("Severity 3, No response to 'offline query' request - no offline inverters");
    }
}

##
## Try to register known inverter
##

sub register_known_inverter {
    my $serial_number = shift;
    pmu_log("Severity 2, Try to register known serial number: $serial_number");

    # send register address (serial number followed by 1 byte address we allocate to inverter)
    $serial_num_response = pack( "A*", $serial_number );
    my @register_address = unpack( "C*", $serial_num_response );
    push( @register_address, $next_inverter_address );
    $address_response = send_request( 0x00, $CTRL_FUNC_CODES{"REGISTER"}{"SEND_REGISTER_ADDRESS"}, \@register_address );
    if ($address_response) {

        # check register acknowledgement
        my $len                      = length($address_response);
        my $register_acknowledgement = unpack( "C", $address_response );
        if ( $register_acknowledgement == 06 ) {
            pmu_log("Severity 1, Inverter $serial_number acknowledged registration");

            # request inverter ID
            $inverter_id_response =
              send_request( $next_inverter_address, $CTRL_FUNC_CODES{"READ"}{"QUERY_INVERTER_ID"} );
            if ($inverter_id_response) {
                my $len         = length($inverter_id_response);
                my $inverter_id = unpack( "A*", $inverter_id_response );
                pmu_log("Severity 1, Connected to inverter: $inverter_id");

                # remember this inverter
                $timestamp                                      = get_timestamp();
                $inverters{$next_inverter_address}{"id_string"} = $inverter_id;
                $inverters{$next_inverter_address}{"serial"}    = $serial_number;
                $inverters{$next_inverter_address}{"connected"} = $timestamp;
                $inverters{$next_inverter_address}{"max"}       = {
                    "pac" => {
                        "watts"     => 0,
                        "timestamp" => $timestamp
                    }
                };

                $inverters{$next_inverter_address}{"daily_retrieved"} = 0;
                set_power_limit($next_inverter_address, 100, 10);                   #Ensure that the inverter is set at a power limit of 100% at startup
                $inverters{$next_inverter_address}{"daily_retrieved_value"} = 0;
                $inverters{$next_inverter_address}{"daily_stored"} = 0;

                # If an MQTT power limit command was retained, apply it now
                if (defined $mqtt_limit_command) {
                    set_power_limit($next_inverter_address, $mqtt_limit_command, 10);
                    pmu_log("Severity 1, MQTT power limit $mqtt_limit_command% applied to newly registered inverter");
                }

                $next_inverter_address++;
            }
            else {
                pmu_log("Severity 2, No response to 'query inverter id' request for known inverter $serial_number");
            }
        }
        else {
            pmu_log("Severity 1, Inverter register acknowledgement incorrect for known inverter $serial_number. Expected 06, received $register_acknowledgement");
        }
    }
    else {
        pmu_log("Severity 2, No response to 'send register address' request for known inverter $serial_number");
    }
}

##
## Set inverter power limit
##
sub set_power_limit {
    my ($inverter_address, $percent_limit, $ramp_time_secs) = @_;

    # Clamp values to safe ranges
    $percent_limit = 99 if $percent_limit > 99;
    $percent_limit = 5   if $percent_limit < 5;             # To ensure that the inverter does not shut down without being able to put it back online
    
    my $ramp_time_secs = 30;  # Always use 30 seconds as requested

    my @data = ($percent_limit, $ramp_time_secs);

    my $success = send_request(
        $inverter_address,
        { "REQUEST" => [ 0x13, 0x20 ], "RESPONSE" => "" },  # No expected response
        \@data
    );

    if ($success) {
        pmu_log("Severity 1, Power limit set to $percent_limit% over $ramp_time_secs seconds for inverter $inverter_address");
        $inverters{$inverter_address}{"power_limit"} = {
            percent => $percent_limit,
            ramp_time => $ramp_time_secs,
        };
        return 1;
    } else {
        pmu_log("Severity 1, Failed to set power limit for inverter $inverter_address");
        return 0;
    }
}

##
## MQTT command listener
##

sub init_mqtt_command_listener {
    my $host = $config->mqtt_host;
    my $port = $config->mqtt_port;
    my $username = $config->mqtt_user;
    my $password = $config->mqtt_password;
    my $command_topic = $config->mqtt_command_topic;
    my $status_topic  = $config->mqtt_response_topic;

    $mqtt = AnyEvent::MQTT->new(
        host     => $host,
        port     => $port,
        user_name => $username,
        password  => $password,
        keep_alive_timer => 60,
        client_id => "eversolar_listener_" . int(rand(10000)),
    );

    $mqtt->subscribe(
        topic => $command_topic,
        qos   => 1,
        callback => sub {
            print ">>> MQTT callback triggered!\n";
            my ($topic, $message) = @_;
            my $payload = $message;
            pmu_log("Severity 1, MQTT command received: $payload");

            if ($payload =~ /^limit power (\d{1,3})$/i) {
                my $limit = $1;
                $limit = 99 if $limit > 99;
                $limit = 5   if $limit < 5;
                $mqtt_limit_command = $limit;
                $last_power_limit = $limit;
                my $response = encode_json({ status => "Power limit set to $limit%" });
                $mqtt->publish(topic => $status_topic, message => $response);
            }
        }
    );

    # Keep AnyEvent's event loop alive using a recurring timer
my $mqtt_timer = AnyEvent->timer(
    after    => 1,
    interval => 1,
    cb       => sub {
        # Nothing needed here; just keep AnyEvent ticking
        1;
    },
);


    pmu_log("Severity 1, MQTT command listener initialized on $command_topic");
}


##
## Write a log file entry
##

sub pmu_log {
    my $msg = shift;

    ( my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst ) = localtime(time);
    my $timestamp = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec );

    # 9th letter is the severity print substr($msg,9,1);
    if ( $config->options_debug >= substr( $msg, 9, 1 ) ) {
        print sprintf( "%s: %s\n", $timestamp, $msg );
        if ( $config->options_output_to_log != 0) {
            open( OUT, ">>" . $config->options_log_file )
              or die "Cannot open file " . $config->options_log_file . " for writing\n";
            printf( OUT "%s: %s\n", $timestamp, $msg );
            close OUT;
        }

    }
}

##
##    Validate data packet - calculate and verify checksum
##

sub validate_checksum {
    my @packet = @_;
    my $csum   = 0;
    my $len    = scalar(@packet);
    for ( $i = 0 ; $i < $len - 2 ; $i++ ) {
        $csum += $packet[$i];
    }

    # packets with all zeroes pass checksum test, but are invalid
    return ( $csum > 0 ) && ( $csum == ( ( $packet[ $len - 2 ] << 8 ) + $packet[ $len - 1 ] ) );
}

##
##    Parse data packet - put two bytes together
##

sub parse_packet {
    my @packet = @_;
    my @data;
    my $j   = 0;
    my $len = scalar(@packet);
    for ( $i = 0 ; $i < $len ; $i += 2 ) {
        $data[ $j++ ] = ( $packet[$i] << 8 ) + $packet[ ( $i + 1 ) ];
    }
    return @data;
}


##
##    Establish socket connection to inverter
##

sub inverter_connect {
    my $connected = 0;
    while ( !$connected ) {
            pmu_log("Severity 1, Connecting to the serial port");
            serial_connect();
        

        $next_inverter_address = START_INVERTER_ADDRESS;

        pmu_log("Severity 2, Asking all inverters to re-register");
        $connected = re_register_inverters();
    }

    # reset some "last" vars
    $last_min  = -1;
    $e_last_wh = -1;
}

##
## get current timestamp
##

sub get_timestamp {
    ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
    return sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec );
}

##
## START OF PROGRAM
##

##
## New sub routine with the old main loop to ensure the logic of the previous while (42) loop does not block the MQTT listener subroutine

sub main_loop {
    my $timestamp = get_timestamp();
    
    AnyEvent->now_update;

    $timestamp = get_timestamp();

    # connect to inverter if not connected (!$sock)
    my $combined_power  = 0;
    my $combined_daykwh = 0;
    my $d365            = 0;

    if ( !$sock ) {
        inverter_connect();
        
        pmu_log("Severity 2, Delaying 10 seconds after inverter_connect before polling...");
        my $delay = AnyEvent->timer(
            after => 10,
            cb => sub {
                main_loop();  # Resume after delay
            }
        );
        return;


    }

    my $sleep_time = 0;


    # aggressive polling when no inverters connected
    while ( keys(%inverters) == 0 ) {
        register_inverter();

        # Check for sock presence, sometimes sock is gone
        if ( !$sock ) {
            pmu_log("Severity 1, no valid sock present");
            last;
        }

        $sleep_time_cnt++;

        # Retry with increasing delay: start at 10s, increase every 5 tries, max 60s
        my $sleep_time = 10 * floor($sleep_time_cnt / 5 + 1);
        $sleep_time = 60 if $sleep_time > 60;

        pmu_log("Severity 2, No inverters registered yet, sleeping for $sleep_time seconds");

        my $delay = AnyEvent->timer(
            after => $sleep_time,
            cb => sub {
                pmu_log("Severity 3, Delay complete during inverter connect");
                main_loop();  # Continue the loop again
            }
        );
        return;  # Exit current main_loop cycle
    }


    $timestamp = get_timestamp();

    # see if there are any new inverters every once in a while (every minute)
    if ( $min != $last_min ) {
        pmu_log("Severity 2, Asking for any inverters to register");
        register_inverter();
    }

    # request data from each connected inverter
    $combined_power  = 0;
    $combined_daykwh = 0;
    foreach $inverter ( keys(%inverters) ) {
        $response = send_request( $inverter, $CTRL_FUNC_CODES{"READ"}{"QUERY_NORMAL_INFO"} );
        if ($response) {

            # good response - reset response_timeout_count
            $inverters{$inverter}{"response_timeout_count"} = 0;

            my $len  = length($response);
            my @data = parse_packet( unpack( "C$len", $response ) );

            my $e_today_kwh = $data[ $DATA_BYTES{'E_TODAY'} ] / 100;
            my $e_today_wh  = $e_today_kwh * 1000;
            my $e_total = $data[ $DATA_BYTES{'E_TOTAL'} ] / 10 + $data[ $DATA_BYTES{'NA_1'} ] * 65535 / 10;   # NA_1 is actually upper bytes of total production
            my $pac     = $data[ $DATA_BYTES{'PAC'} ];
            if ( $data[ $DATA_BYTES{'TEMP'} ] >= 0x8000 ) {
                $data[ $DATA_BYTES{'TEMP'} ] -= 0x10000;
            }                                                                                                 # Temperature is signed, -0.1 = 0xFFFF
            my $temp      = $data[ $DATA_BYTES{'TEMP'} ] / 10;
            my $dc_volt   = $data[ $DATA_BYTES{'VPV'} ] / 10,
            my $dc_imp    = $data[ $DATA_BYTES{'IPV'} ] / 10,
            my $ac_volt   = $data[ $DATA_BYTES{'VAC'} ] / 10,
            my $ac_imp    = $data[ $DATA_BYTES{'IAC'} ] / 10,

            $combined_power = $combined_power + $data[ $DATA_BYTES{'PAC'} ];
            $combined_daykwh = $combined_daykwh + $data[ $DATA_BYTES{'E_TODAY'} ] / 100;
           
            $d365 = $e_total - $inverters{$inverter}{"daily_retrieved_value"};
            
            pmu_log("Severity 3, " . $inverters{$inverter}{"serial"} . " output: $pac W, Total: $e_total kWh, Today: $e_today_kwh kWh, 365 days : $d365 " );

            $inverters{$inverter}{"data"} = {
                "timestamp"    => $timestamp,
                "pac"          => $data[ $DATA_BYTES{'PAC'} ],
                "e_today"      => $e_today_kwh,
                "e_total"      => $e_total,
                "vpv"          => $data[ $DATA_BYTES{'VPV'} ] / 10,
                "vpv2"         => $data[ $DATA_BYTES{'VPV2'} ] / 10,
                "ipv"          => $data[ $DATA_BYTES{'IPV'} ] / 10,
                "ipv2"         => $data[ $DATA_BYTES{'IPV2'} ] / 10,
                "vac"          => $data[ $DATA_BYTES{'VAC'} ] / 10,
                "iac"          => $data[ $DATA_BYTES{'IAC'} ] / 10,
                "frequency"    => $data[ $DATA_BYTES{'FREQUENCY'} ] / 100,
                "d365"         => $d365,
                "impedance"    => $data[ $DATA_BYTES{'IMPEDANCE'} ],
                "hours_up"     => $data[ $DATA_BYTES{'HOURS_UP'} ],
                "op_mode"      => $data[ $DATA_BYTES{'OP_MODE'} ],
                "temp"         => $temp,
                "total_power"  => $combined_power,
                "total_daykwh" => $combined_daykwh
            };



            if ( $data[ $DATA_BYTES{'PAC'} ] > $inverters{$inverter}{"max"}{"pac"}{"watts"} ) {
                $inverters{$inverter}{"max"}{"pac"} = {
                    "timestamp" => $timestamp,
                    "watts"     => $data[ $DATA_BYTES{'PAC'} ]
                };
            }



         
           ###############################################################################
           ##
           ##
           ##
           ##    Data to MQTT (Home Assistant)
           ##
           ##
           ##
           ###############################################################################
           if ( $config->mqtt_enabled ) {
               pmu_log("Severity 3: MQTT Start");
               #retrieve mqtt config info
               my $mqtt_host           = $config->mqtt_host;
               my $mqtt_port           = $config->mqtt_port;
               my $mqtt_user           = $config->mqtt_user;
               my $mqtt_password       = $config->mqtt_password;
               my $mqtt_topic_prefix   = $config->mqtt_topic_prefix;
               my $mqtt_inverter_model = $config->mqtt_inverter_model;


               my $mqtt_serial = $inverters{$inverter}{'serial'};


               my $cmd;
               pmu_log("Severity 3: MQTT Config info is read");


               my %mqtt_data = (
                   pac => $inverters{$inverter}{'data'}{'pac'},
                   max_power_today => $inverters{$inverter}{'max'}{'pac'}{'watts'},
                   d365 => $inverters{$inverter}{'data'}{'d365'},
                   total_daykwh => $inverters{$inverter}{'data'}{'total_daykwh'},
                   e_total => $inverters{$inverter}{'data'}{'e_total'},
                   temp => $inverters{$inverter}{'data'}{'temp'},
                   impedance => $inverters{$inverter}{'data'}{'impedance'},
                   frequency => $inverters{$inverter}{'data'}{'frequency'},
                   iac => $inverters{$inverter}{'data'}{'iac'},
                   ipv => $inverters{$inverter}{'data'}{'ipv'},
                   vac => $inverters{$inverter}{'data'}{'vac'},
                   vpv => $inverters{$inverter}{'data'}{'vpv'},
                   op_mode => $inverters{$inverter}{'data'}{'op_mode'},
                   hours_up => $inverters{$inverter}{'data'}{'hours_up'},
                   timestamp => $inverters{$inverter}{'data'}{'timestamp'},
                   connected => $inverters{$inverter}{'connected'},
                   power_limit => $inverters{$inverter}{"power_limit"}{"percent"},
               );
               pmu_log("Severity 3: MQTT inverter hash is flattened");

               # Subroutine for Home Assistant Device/Entity configuration
              sub ha_disc_config {
                       my $mqtt_serial_HA = $inverters{$inverter}{'serial'};
                       my %config_data = (
                           device => {
                               identifiers => [
                                   $mqtt_serial_HA,
                                   ],
                               manufacturer => "Eversolar",
                               model => $mqtt_inverter_model,
                               name => "Solar Inverter"
                           },
                           state_topic => "$mqtt_topic_prefix/$mqtt_serial_HA/$_[0]",
                           unique_id => "$mqtt_serial_HA\_$_[0]",
                           state_class => "measurement",
                       );
                     if ( $_[0] eq "pac" ){
                           $config_data{'icon'} = "mdi:solar-power";
                           $config_data{'name'} = "PV Solar Power Right Now";
                           $config_data{'unit_of_measurement'} = "W";
                           $config_data{'device_class'} = "power";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "max_power_today" ){
                           $config_data{'icon'} = "mdi:solar-power";
                           $config_data{'name'} = "PV Maximum Solar Power Today";
                           $config_data{'unit_of_measurement'} = "W";
                           $config_data{'device_class'} = "power";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "d365" ){
                           $config_data{'icon'} = "mdi:solar-power";
                           $config_data{'name'} = "PV Last 365 Days Production";
                           $config_data{'unit_of_measurement'} = "kWh";
                           $config_data{'device_class'} = "energy";

                       } elsif ( $_[0] eq "total_daykwh" ){
                           $config_data{'icon'} = "mdi:solar-power";
                           $config_data{'name'} = "PV Total Energy Today";
                           $config_data{'unit_of_measurement'} = "kWh";
                           $config_data{'device_class'} = "energy";

                       } elsif ( $_[0] eq "e_total" ){
                           $config_data{'icon'} = "mdi:solar-power";
                           $config_data{'name'} = "PV Total Energy Production";
                           $config_data{'unit_of_measurement'} = "kWh";
                           $config_data{'device_class'} = "energy";
                           $config_data{"state_class"} = "total_increasing";

                       } elsif ( $_[0] eq "temp" ){
                           $config_data{'icon'} = "mdi:temperature-celsius";
                           $config_data{'name'} = "PV Inverter Temperature";
                           binmode(STDOUT, ":utf8");
                           $config_data{'unit_of_measurement'} = "<C2><B0>C";
                           $config_data{'device_class'} = "temperature";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "impedance" ){
                           $config_data{'icon'} = "mdi:omega";
                           $config_data{'name'} = "PV Inverter Impedance";
                           $config_data{'unit_of_measurement'} = "Ohm";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "frequency" ){
                           $config_data{'icon'} = "mdi:sine-wave";
                           $config_data{'name'} = "PV AC Frequency";
                           $config_data{'unit_of_measurement'} = "Hz";
                           $config_data{'device_class'} = "frequency";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "iac" ){
                           $config_data{'icon'} = "mdi:current-ac";
                           $config_data{'name'} = "PV AC Current";
                           $config_data{'unit_of_measurement'} = "A";
                           $config_data{'device_class'} = "current";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "ipv" ){
                           $config_data{'icon'} = "mdi:current-ac";
                           $config_data{'name'} = "PV Current";
                           $config_data{'unit_of_measurement'} = "A";
                           $config_data{'device_class'} = "current";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "vac" ){
                           $config_data{'icon'} =  "mdi:sine-wave";
                           $config_data{'name'} = "PV AC Voltage";
                           $config_data{'unit_of_measurement'} = "V";
                           $config_data{'device_class'} = "voltage";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "vpv" ){
                           $config_data{'icon'} = "mdi:sine-wave";
                           $config_data{'name'} = "PV Voltage";
                           $config_data{'unit_of_measurement'} = "V";
                           $config_data{'device_class'} = "voltage";
                           $config_data{'state_class'} = "measurement";

                       } elsif ( $_[0] eq "op_mode" ){
                           $config_data{'icon'} = "mdi:cog";
                           $config_data{'name'} = "PV Operation Mode";

                       } elsif ( $_[0] eq "hours_up" ){
                           $config_data{'icon'} = "mdi:timer-cog";
                           $config_data{'name'} = "PV Total Uptime";
                           $config_data{'unit_of_measurement'} = "hours";
                           $config_data{"state_class"} = "total_increasing";

                       } elsif ( $_[0] eq "timestamp" ){
                           $config_data{'icon'} =  "mdi:update";
                           $config_data{'name'} = "PV Updated At";
                           $config_data{'device_class'} = "timestamp";
                       } elsif ( $_[0] eq "connected" ){
                           $config_data{'icon'} = "mdi:connection";
                           $config_data{'name'} = "PV Connected At";
                           $config_data{'device_class'} = "timestamp";
                        } elsif ( $_[0] eq "power_limit" ) {
                            $config_data{'icon'} = "mdi:transmission-tower-export";
                            $config_data{'name'} = "PV Power Limit";
                            $config_data{'unit_of_measurement'} = "%";
                            $config_data{'device_class'} = "power_factor";
                            $config_data{'state_class'} = "measurement";

                       } else {
                           print "$_[0] - No data passed, or hash is corrupted";
                                              # Failure on writing to influxdb
                           pmu_log("Severity 1: $_[0] - No data passed, or hash is corrupted");
                       };

                       return %config_data;
                   }
                   # Convert Hash to JSon string
                   sub jsonify_config {
                       my %config_hash = @_;
                       my $config_json = encode_json \%config_hash;
                       # Return our built discovery config
                       return $config_json;
                   }
               #Publishing MQTT messages
               keys %mqtt_data;
               while(my($k, $v) = each %mqtt_data)
               {
                   #Publishing Auto Discovery Messages for home assistant if enabled
                   if( $config->mqtt_ha_discovery ) {
                       my $config_send = jsonify_config(ha_disc_config("$k"));
                       if ( $config->mqtt_enable_pass ){

                           $cmd = `mosquitto_pub -h $mqtt_host -p $mqtt_port -u "$mqtt_user" -P "$mqtt_password" -q 0 -t 'homeassistant/sensor/$mqtt_topic_prefix/$mqtt_serial\_$k/config' -m '$config_send'`;
                       } else {
                           $cmd = `mosquitto_pub -h $mqtt_host -p $mqtt_port -q 0 -t 'homeassistant/sensor/$mqtt_topic_prefix/$mqtt_serial\_$k/config' -m '$config_send'`;
                       }
                       chomp $cmd;
                       sleep 0.5;
                       pmu_log("Severity 3: MQTT $k's HA configuration is published");
                   }
                   #Publishing Sensor Entity State Messages
                   my @ts_data = ("timestamp", "connected");
                   if( grep( /$k/ , @ts_data ) ){
                       my $tz = strftime("%z", localtime());
                       my $tz_h = substr($tz, 0, -2);
                       my $tz_m = substr($tz,-2);
                       $v = "$v$tz_h:$tz_m";
                   }

                   if ( $config->mqtt_enable_pass ){
                       $cmd = `mosquitto_pub -h $mqtt_host -p $mqtt_port -u "$mqtt_user" -P "$mqtt_password" -q 1 -t '$mqtt_topic_prefix/$mqtt_serial/$k' -m '$v'`;
                   } else {
                       $cmd = `mosquitto_pub -h $mqtt_host -p $mqtt_port -q 1 -t '$mqtt_topic_prefix/$mqtt_serial/$k' -m '$v'`;
                   }
                   chomp $cmd;
                   sleep 0.5;
                   pmu_log("Severity 3: MQTT $k = $v is published");
               }
               pmu_log("Severity 3: Mqtt messages published");
             }
# end of MQTT           
            
            if ( $hour == 1 && $min == 1 ) {
                if ( $inverters{$inverter}{"daily_retrieved"} == 1 ) {
                    $inverters{$inverter}{"daily_retrieved"} = 0;
                    $inverters{$inverter}{"daily_retrieved_value"} = 0;
                    pmu_log("Severity 3, daily retrieved reset");
                }
                if ($inverters{$inverter}{"daily_stored"} == 1) {
                    $inverters{$inverter}{"daily_stored"} = 0;
                    pmu_log("Severity 3, daily stored reset");
                }
            }
        }
        else {
            $inverters{$inverter}{"response_timeout_count"}++;
            pmu_log("Severity 2, "
                  . $inverters{$inverter}{"serial"}
                  . " lost contact with inverter ("
                  . $inverters{$inverter}{"response_timeout_count"}
                  . " time(s))" );

            if ( $inverters{$inverter}{"response_timeout_count"} == 3 ) {
                pmu_log( "Severity 1, " . $inverters{$inverter}{"serial"} . " lost contact with inverter, forgetting inverter" );


                # forget about the inverter
                delete $inverters{$inverter};
                
                # Delete the log file monthly to prevent the solution from filling the disk
                if ( $config->options_clean_log && $mday == 1 && keys(%inverters) == 0 && $hour == 1 ) {
                    unlink( $config->options_log_file );

                }


            }

            # break out of foreach($inverters... and go to start of main loop
            last;
        }

    }

    $last_min = $min;

    # Apply any pending MQTT power limit command
    if (defined $mqtt_limit_command) {
        foreach my $addr (keys %inverters) {
            set_power_limit($addr, $mqtt_limit_command, 10);
        }
        pmu_log("Severity 1, Applied MQTT power limit: $mqtt_limit_command%");
        $mqtt_limit_command = undef;
    }


}


###############################################################################
##
##
##
##    Main Loop
##
##
##
##
##
###############################################################################
my $main_loop_timer = AnyEvent->timer(
    after    => 0,
    interval => $config->options_query_inverter_secs,
    cb       => sub {
        main_loop();
    }
);

# Timer to refresh the power limit midway between inverter polling, and every x minutes (no more than 10) defined by eversolar.ini options
my $power_limit_refresh_timer = AnyEvent->timer(
    after    => $config->options_query_inverter_secs / 2,
    interval => $config->options_power_limit_refresh_mins * 60,
    cb       => sub {
        foreach my $inverter (keys %inverters) {
            set_power_limit($inverter, $last_power_limit, 30);
            pmu_log("Severity 2, Refreshed power limit $last_power_limit% for inverter $inverter");
        }
    }
);


AnyEvent->condvar->recv;



pmu_log("Severity 1, Main loop ended - about to exit - why?");

if ( $config->options_communication_method eq "eth2ser" ) {
    close $sock;
}
elsif ( $config->options_communication_method eq "serial" ) {
    $sock->close;
}
