Here's how to setup your linux box for the perl software. This may work under Windows as well, please contact us, if you have success with that.

Remember that there is a quick way: download the Raspberry Pi image, and modify the ini file as described on a separate page here [Setup\_from\_image\_file](Setup_from_image_file.md)

The below instructions do require some skills

# Introduction #

Some knowledge of linux command line scripting is an advantage, but people have come through here without _any_ computer skills.

Again, we strongly recommend using the predefined SD card, as you will get a good setup with remote control ability and less fuss.



# Detailed installation instructions #

To make this work on a Raspberry pi, you need a few packages:

```
# Open a command line / LXTerminal on the desktop, install GIT

sudo apt-get install git-core build-essential libssl-dev


# Fetch the code:
git clone https://github.com/solmoller/eversolar-monitor
If the above line is not working, use this one and log an issue here on github:
(  git clone https://code.google.com/p/eversolar-monitor/)


# Now you own a folder named eversolar-monitor
# Here you edit the .ini file to fit your configuration




# Now you just need to install som requirements, all from the command line

# Update libraries
sudo apt-get update
sudo apt-get install libappconfig-perl
sudo apt-get install gcc-4.7
# (wait at least an hour)
sudo apt-get install libdbi-perl 
sudo apt-get install libjson-perl

sudo apt-get install libhttp-server-simple-perl
sudo apt-get install cpanminus
sudo cpanm DBD::SQLite

# If you use a serial port:

apt-get install libdevice-serialport-perl
#Serial ports have a tencency to hang the RPI inless you update it
sudo apt-get install ca-certificates
rpi-update
# reboot
#And you’re ready to go - after modifying the .ini file start the script like this:

sudo perl eversolar.pl
```

### Stability ###
Many users have stability problems, loosing contact with their Raspberry Pi, in that case edit /boot/cmdline.txt, with  "dwc\_otg.speed=1 dwc\_otg.fiq\_fix\_enable=0", this will stabilize the Raspberry Pi. The easy way to do this is to edit the file by insertind the SD card in another computer.

## Setting up the script's ini file ##
The logging is controlled by the file eversolar.ini, this is how you should set it up. Most settings should be left unchanged, the typical changes are listed in **bold** below

```
[options]
query_inverter_secs = 10		# how often to request data from the inverter and write to log file
debug = 1				# Debug level , 0 = none, 1 is high priority, 3 is everything, also output packets sent to and received from the inverter
log_file = "/var/log/eversolar"		# make sure the user executing the script can write to this file
communication_method = "serial"	# "eth2ser" or "serial". defines wether you are using an ethernet to serial converter to connect to the inverter, or just a serial port
strings = 1      # number of PV panel strings (panels wired together) connected to your inverter. 1 or 2 supported.
```


**Communication\_method** is to be set, depending on what hardware you use to connect to the inverters

**Strings** is one for Eversolar TL 2000 and below, it is 2 for TL 3000 and above. If you have a TL 3000 or above with just one string attached, **strings** is still to be set to 2. Newer Zeversolar 3000 may have changed firmware and require strings = 1

```
[eth2ser]				# communication_method must be set to "eth2ser" above for ethernet to serial devices
ip_address = "192.168.2.1"
port = 23
```

If you use a ethernet-to-serial adapter, here is where you instruct the software how to connect

```
[serial]				# communication_method must be set to "serial" above for serial comms
port = "/dev/ttyUSB0"
```

ttyUSB0 is the standard USB port on a Raspberry Pi

```
[pvlog]				# upload generation to pv-log.com
enabled = 1
FTPServeradresse = "ftp.pv-log.com"
interval = 1		        # 5 minutes, interval between logs - beware, pv-log is sluggish and only updates once per hour
username = "idxxxx"             # taken  from pv-log settings
Password = "0hxxxxx"
```

The **PV-log** section is to be modified if you wish to upload to pv-log.com.

To find pv-log.com api and password, go to 'my profile' and find the API key
Under Automatic data import, set it to
```
Data logger company    :     Other manufacturer/own construction
Data logger model      :     Datenformat Solarlog
Transfer type          :     FTP
```

**Username** and **password** is _not_ your normal logon credentials to pv-log, they are to be read out from this place on pv-log.com's web page.


```
[pvoutput]				# upload generation to pvoutput.org
enabled = 1
api_key = "99ccfxxxxxxxxxxxxxxxxxxxxxxxxxxx2"
status_interval_mins = 5		# 5 or 10 minutes, depending on your pvoutput.org setting
add_status_url = "http://pvoutput.org/service/r2/addstatus.jsp"
# duplicate the next line if you have multiple inverters and replace the serial numbers with your inverter serial numbers and the matching pvoutput system ids
system_id B882000A127D0 = 99999 # system_id inverter_serial_number = pvoutput_system_id
system_id B882000A127D0 = 99998 # system_id inverter_serial_number = pvoutput_system_id

```

The **pvoutput** section is to be modified if you wish to upload to pvoutput.org.

Under "Account settings" in Pvoutput enable "API Access", **api\_key** can then be found in your settings and copy pasted to the ini file.

**System\_id** lines are setting up serial numbers vs pvoutput system id's, the ini file has two examples to modify. This enables the solution to ensure that the proper serial number is mapped to the same pvoutput.org system each time.

In addition you might want to use pvoutput.org's team function to team up your individual systems, enabling reporting of total production on their web page, this can be done for free on the web page, despite descriptions that imply that it is not possible.

```
[seg]					# upload generation to smartenergygroups.com
enabled = 0
upload_interval_mins = 1
site_id = "site_1234abcd"
device = "solar"			# device name
power_stream = "p"			# stream name for power stream
energy_stream = "e"		# stream name for energy stream
api_url = "http://api.smartenergygroups.com/api_sites/stream"
```

Setting up upload to smartenergygroups.com

**site\_id** is found on smartenergygroups.com in your profile

```
[web_server]
enabled = 1
port = 3837
```

The web server is set up on your own computer, and normally it can only be reached as 'ip of computer':3837, typically something like http://192.168.1.10:3837

If you want to be able to reach this web page from the internet, you have to have IPV6 and port forwarding. The script needs some modification as well:

```
@@ -176,8 +177,8 @@ if($config->web_server_enabled) {
{
package SolarWebServer;

- use HTTP::Server::Simple::CGI;
- use base qw(HTTP::Server::Simple::CGI);
+ use HTTP::Server::Simple::CGI::PreFork;
+ use base qw(HTTP::Server::Simple::CGI::PreFork);
use JSON;
use File::Basename;
```

You will have to install HTTP::Server::Simple::CGI::PreFork, it is recommended to use CPAN for this.

The web page looks something like this

![http://i1360.photobucket.com/albums/r654/solmoller/Eversolar_zpscbcd1e33.jpg](http://i1360.photobucket.com/albums/r654/solmoller/Eversolar_zpscbcd1e33.jpg)
