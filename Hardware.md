Known good and bad configurations of hardware

# Introduction #

The typical setup is a Raspberry Pi with a USB to RS485/422 industrial serial port. RS422 is the port standard on Eversolar inverters, but RS485 ports can also communicate with the inverters when they are wired for half duplex.

![http://i1360.photobucket.com/albums/r654/solmoller/eversolar_setup_zps34665aa4.jpg](http://i1360.photobucket.com/albums/r654/solmoller/eversolar_setup_zps34665aa4.jpg)

# Details #
## Cabling ##
Cabling can be done through cutting open a network cable and rewire according to the manual - or use a network crimper tool for a sturdy, nice looking solution

Here's an example of how to connect an RS422 adapter

|Eversolar pin|colour|Eversolar signal|Description|
|:------------|:-----|:---------------|:----------|
|1            |yellow|RXD+            |Yellow RXD+ Input Data + (B) Input|
|2            |white |RXD-            |White RXD- Input Data – (A) Input|
|3            |orange|TXD+            |Orange TXD+ Output Data + (B) Output|
|4            |black |gnd             |Black GND GND Device ground supply pin|
|6            |red   |TXD-            |Red TXD- Output Data – (A) Output|


You can interconnect additional Eversolar inverters with regular RJ45 network patch cables

Here's an example of how to connect an RS485 adapter


|Eversolar pin|Eversolar signal|RS485|
|:------------|:---------------|:----|
|1            |RXD+            |Data + |
|2            |RXD-            |Data – |
|3            |TXD+            |Data +|
|4            |gnd             | GND |
|6            |TXD-            |Data – |

And another example

|Eversolar Pin|Colour|Name|RS 485 Pin|Colour|Name|
|:------------|:-----|:---|:---------|:-----|:---|
|1            |Orange/white|TX\_A|3         |Green/white|RX\_A|
|2            |Orange|TX\_B|6         |Green |RX\_B|
|3            |Green/white|RX\_A|1         |Orange/white|TX\_A|
|4            |Blue  |GND |7         |Brown/white|GND |
|5            |Blue/white|GND |8         |Brown |GND |
|6            |Green |RX\_B|2         |Orange|TX\_B|
|7            |NC    | |4   |NC        | |
|8            |NC    | |5   |NC        | |


### Inverted polarity ###
A few users have accidentally switched plus and minus on their cabling, strangely, the Eversolar inverters reply, but unsuccessfull:
```
Sending: aa 55 01 00 00 00 10 00 00 01 10
received packet from inverter:
**95 55 ff ff ff** df f7 ff fd d7 00 95 55 ff ff ff df
ff ff fd df 00
```
The ff ff ff ff indicates the inverted polarity, they should be 00 00 00 00
## Termination ##
There is debate on the necessity of termination, it appears not to be required with cable lengths under 10 meters
## Known good computers ##
Raspberry Pi version B. Versions A, A+, B+ and 2 should work fine. Regular PC's are also used

## Known good USB to RS22 ports ##
USB-RS422-WE-LLLL-CU
## Known good USB to RS485 ports ##
FTDI based ports

http://www.ebay.co.uk/itm/USB-2-0-to-RS-485-RS485-RJ45-RJ-45-Serial-Adapter-Converter-FTDI-FT232-FT232R-/170792123589?

## Known **bad** USB to RS485 ports ##
[![](http://www.frederiksson.dk/danfoss/rs485.jpg)](http://www.frederiksson.dk/danfoss/rs-485.html)
The pc-sintech adapter is known to ship with a faulty diode, the image links to a description on how to fix it
## Known good ethernet to RS485 ##
USR-TCP-RS232-300
