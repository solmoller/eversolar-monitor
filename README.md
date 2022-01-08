# eversolar-monitor




Script to capture data and create statistics from Eversolar/zeversolar Solar Inverters using RS485 interface and a RS485 to ethernet adapter or a RS485 USB adapter.

Based on Steve Cliffe's <steve@sjcnet.id.au> Eversolar PMU logger script (http://www.sjcnet.id.au/computers/eversolar-inverter-monitoring-with-linux)

Tested with the following inverters

  * TL1500AS Inverter connected to an ethernet to serial converter
  * TL2000 (multiple) connected to a Raspberry Pi through USB->RS485
  * TL3000 (multiple) connected to a Raspberry Pi through USB->RS485 and through Eth->RS485 on a 'normal' linux pc
  * Volta TL3000 (multiple) through USB->RS485
  * TL4000  
  * TL5000 connected to an ethernet to serial converter 
  * TL5400  (multiple) through USB->RS485


So most, if not all Eversolar inverters should be working with most, if not all flavours of linux through both ethernet to serial or USB to RS485 connections.

The script reads the inverter data, stores it in a local sqlite database, then sets up optional:
 
  * Own web server
  * Upload to pvoutput.org
  * Upload to pv-log.com
  * Upload to smartenergygroups.com
  * Upload to Domoticz
  * Integration to Home Assistant, HASS
  

Please consult the wiki for further information here https://github.com/solmoller/eversolar-monitor/blob/wiki/Introduction.md

When you make the logger work, please join our pvoutput.org team _Eversolar perl loggers_ here http://pvoutput.org/listteam.jsp?tid=485 (you'll have to have the system running for 5 days to be allowed in)

To find pv-log.com api and password, go to 'my profile' and find the API key
Under Automatic data import, set it to
{{{
Data logger company    :     Other manufacturer/own construction
Data logger model      :     Datenformat Solarlog
Transfer type          :     FTP
}}}

And read out the username and password for the FTP account from there, the username (id1234) and password are to be entered in fhe ini file. Do not use your regular userid to pv-log!


We do try to test the software and it is working well for quite a number of people on most continents. It is difficult for me to test the installation instructions as I know the software and its requirements all too well. I need feedback to improve both the software and the supporting instructions. We also would like help maintaining the wiki

  * If you have trouble, please create an "Issue". We will help as best we can
  * If you find a fault in the software please create an "Issue"
  * All suggestions for improvement or new features will be well received (create an Issue for this as well)
  * If you want to work on the software yourself, that too is welcome
  * Of course - I you have success, we would like to hear about that too

You can consult the a wiki being for this project, with installation instructions and known good configurations, a downloadable image for raspberry is also available from there, https://github.com/solmoller/eversolar-monitor/blob/wiki/Introduction.md

Here's a how the build-in web server may look like:![(Screenshot](http://i1360.photobucket.com/albums/r654/solmoller/Eversolar_zpscbcd1e33.jpg)

