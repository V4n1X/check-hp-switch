# check-hp-switch
HP / Aruba Switch CRC/Packet Drop Check (Nagios / Icinga)

This script checks HP/Aruba (also modular) switches (and maybe all others switches with common MIBs) on every interface for CRC errors & packet errors (in / out).

Tested on Icinga2 (version: r2.9.1-1)

# Original idea from:
check_hp_crc.sh - Version 1.0

by Michael St - 23.10.2014

is121026[at]fhstp.ac.at

# LICENSE
GNU GPLv3

This means: you are allowed to copy and change the script as you like! 

The script is free for download, but be so kind and don´t delete my name and replace it with yours!

# Other:

Help is within the Script (-h)

Debugging is also available (-d)

Performance Data: (-p)

Wors great with pnp4nagios (should work also with nagiosgraph)

# Needed MIBS
Need more SNMP MIBS downloaded -> snmp-mibs-downloader

example: https://packages.debian.org/de/jessie/snmp-mibs-downloader

used MIBs: 	

RMON-MIB

 - IF-MIB

# Files

- INSTRUCTIONS: check_hp_crc_howto.txt

- Script: check_hp_rc.sh
