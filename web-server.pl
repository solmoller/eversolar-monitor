{
    package SolarWebServer;

    use HTTP::Server::Simple::CGI;
    use base qw(HTTP::Server::Simple::CGI);
    use JSON;
    use AppConfig;

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

