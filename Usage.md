#Tips on how to use the script and extract data from the database

# Introduction #

For details on how to set up and connect to the solution, see the software installation page here https://code.google.com/p/eversolar-monitor/wiki/Software_installation

This page is describing how to extract custom data


The script is set up in the eversolar.ini file

The script stores data in a database in a file named db.sql

# Details #
It is possible to extract data on demand from a command line:


```
sudo sqlite3 -csv -header -separator ';' db.sqlite "select serial_number,max(e_today), date(timestamp) from inverter group by serial_number,date(timestamp);" > daily.csv
```

If you run the above from a command line (putty or local xterm), then you might need some patience, expect about a minute of computational time per 5 MB of database file on a Raspberry Pi. The output file daily.scp, contains the production per day:

```
serial_number    max(e_today)    date(timestamp)
B882000A127D0011    6.69    28-10-2012
B882000A127D0013    0.43    29-10-2012
```
If you are looking for hourly productions, this SQL queryl extracts max_production from each inverter by hour:
```
select serial_number,max (e_total), strftime('%Y-%m-%dT%H:00:00.000', timestamp) from inverter group by serial_number ,strftime('%Y-%m-%dT%H:00:00.000', timestamp) 
```


If you don't have sqlite3 on your Raspberry Pi, then install it like this:

```

sudo apt-get update
sudo apt-get install sqlite3
```
