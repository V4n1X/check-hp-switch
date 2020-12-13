#!/bin/bash
#
# Version: master
#
# V4n1X (C)2019
#
# This Script checks HP ProCurve Switches on every Interface for CRC Errors & Packet Errors
# Nagios / ICINGA Plugin
#
# Original idea from:
# check_hp_crc.sh - Version 1.0
# by Michael St - 23.10.2014
# is121026[at]fhstp.ac.at
#
# Informations about MIBs:
#
# used MIBs: 	
#	RMON-MIB
# 	- IF-MIB
#
################
# MIBS variables
################
# get CRC ERRORS on INTERFACES
# CRC_MIB="RMON-MIB::etherStatsCRCAlignErrors"
# CRC_MIB=".1.3.6.1.2.1.16.1.1.1.8" //also possible I think
CRC_MIB="RMON-MIB::etherStatsCRCAlignErrors"
#Get Input Packet Errors
IF_MIB_IN_ERRORS=".1.3.6.1.2.1.2.2.1.14"
#Get Output Packet Errors
IF_MIB_OUT_ERRORS=".1.3.6.1.2.1.2.2.1.20"
# Port Description
PORT_DESC=".1.3.6.1.2.1.2.2.1.2"
#Version
SYSDESC_MIB=".1.3.6.1.2.1.1.1.0"
#Name
SYSNAME_MIB=".1.3.6.1.2.1.1.5.0"
#Location
SYSLOCATION_MIB=".1.3.6.1.2.1.1.6.0"
# bin for snmpwalk
LIBEXEC="/usr/bin/snmpwalk"
#snmp community name
SNMPC="public"
# snmp version
SNMPV="2c"
# host name
HOST=""
# RETURN VALUES:
# OK = 0
# WARNING = 1
# CRITICAL = 2
# UNKNOWN = 3
# Default Values for Warn / Crit
WARN="1000"
CRIT="5000"
# Switch to force debug, alternative -d as parameter
DEBUG=0
#################
# Output Switches
#################
CNTIF=0
# Set Values for Output (CRC Errors)
SETWARNCRC=0
SETCRITCRC=0
SETUNKNOWNCRC=0
# Set Values for Output (Packets)
##Incoming
SETWARNP=0
SETCRITP=0
SETUNKNOWNP=0
##Outgoing
SETWARNP_OUT=0
SETCRITP_OUT=0
SETUNKNOWNP_OUT=0
# other variables
SNMPOUTPUT=""
SNMPOUTDESC=""
CRCPORTSWARN=""
CRCPORTSCRIT=""
CRCOKPERF=""
#####################
# RETURN VALUES
# default: [UNKNOWN]
#####################
# CRC RETURN & value for final return exit
RETURN=3
# RETURN value for incoming packet errors
RETURNPIN=3
# RETURN value for outgoing packet errors
RETURNPOUT=3
###################
# Performance data
###################
PERFDATA=0
PERFDATA_OUT=0
##########################################
# Define variables for system information
##########################################
SYSDESC="-"
SYSNAME="-"
SYSLOCATION="-"
SYSMODEL="-"
if=
ifparray=

# Help function :-)
function print_help 
{
echo "
./check_hp_crc.sh -H HOSTADRESS -C <SNMP COMMUNITY> -v <SNMP VERSION> -w <warning value for ERRORS> -c <critical value for ERRORS>

-H = Hostaddress
-C = SNMP Community (optional, if not set we use public)
-v = SNMP Version (optional, if not set we use 2c)
-w = Warning Threshold (optional, if not set we use 1000)
-c = Critical Threshold (optional, if not set we use 5000)
-p = Enable Performance Data for all Ports)
-d = DEBUG OUTPUT (use with caution!!!)
-h = Help - Print this Help!
"
}

#check command line arguments
# Reset in case getopts has been used previously in the shell.
OPTIND=1

while getopts "H:C:v:w:c:hdpm:" opt; do
    case "$opt" in
    h)
        print_help
        exit 0
        ;;
    H)  HOST=$OPTARG
        ;;
    C)  SNMPC=$OPTARG
        ;;
    v)  SNMPV=$OPTARG
	;;
    w)  WARN=$OPTARG
	;;
    c)  CRIT=$OPTARG
	;;
    d)  DEBUG=1
	;;
    p)  PERFDATA=1
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

# check if warn is smaller than CRIT
if [ "$WARN" -ge "$CRIT" ]; then
	echo "WARN: ${WARN} CRIT: ${CRIT}"
	echo "ERROR - If a WARNING-Threshold is set, you have to set a greater CRITICAL-Threshold too!"
	exit 3;
fi

# some debugging: activate with -d in cli
if [ "$DEBUG" -eq "1" ]; then
# debug out
echo [Debug] = "${DEBUG}"
echo [Host] = "${HOST}"
echo [Snmp Community] = "${SNMPC}"
echo [Snmp Version] = "${SNMPV}"
echo [Warn] = "${WARN}"
echo [Crit] = "${CRIT}"
echo [Perfdata] = "$PERFDATA"
fi

function getSwitchInfo {
SYSDESC1=$($LIBEXEC -v $SNMPV -c $SNMPC $HOST $SYSDESC_MIB| cut -d" " -f8-11 | tr -d '"');
SYSNAME1=$($LIBEXEC -v $SNMPV -c $SNMPC $HOST $SYSNAME_MIB | cut -d" " -f4- | tr -d '"');
SYSLOCATION1=$($LIBEXEC -v $SNMPV -c $SNMPC $HOST $SYSLOCATION_MIB | cut -d" " -f4- | tr -d '"');
SYSMODEL1=$($LIBEXEC -v $SNMPV -c $SNMPC $HOST $SYSDESC_MIB| cut -d" " -f4-6 | tr -d '"');

if [ -n "$SYSDESC1" ]; then
	SYSDESC=$SYSDESC1
else
	echo "[INFO] No system description found!"
fi

if [ -n "$SYSNAME1" ]; then
	SYSNAME=$SYSNAME1
else
	echo "[INFO] No system name found!"
fi

if [ -n "$SYSLOCATION1" ]; then
	SYSLOCATION=$SYSLOCATION1
else
	echo "[INFO] No system location found!"
fi

if [ -n "$SYSMODEL1" ]; then
	SYSMODEL=$SYSMODEL1
else
	echo "[INFO] No switch model found!"
fi
}

function getPortDesc {
IFS=$'\n'   #set separator to newline only
# do the snmpwalk and fetch data for all ports on switch
SNMPOUTDESC+=$($LIBEXEC -v $SNMPV -c $SNMPC $HOST $PORT_DESC);

#for i in "${SNMPOUTDESC[@]}"
for i in "${SNMPOUTDESC[@]}"
do
	if+=($(echo "$i" | cut -d" " -f1 | tr -d '"' | cut -d . -f11))
	ifparray+=($(echo "$i" | cut -d" " -f4- | tr -d '"'))
done
unset IFS
}

function getInterfacesCRCErrors {

# some local variables - clear so far
ifarray=""
crcarrayB=""
crcarray=""
portdescarray=""
IFS=$'\n'   #set separator to newline only

# do the snmpwalk and fetch data for all ports on switch
#SNMPOUT=( $(snmpwalk -v 2c -c public 10.255.30.99 RMON-MIB::etherStatsCRCAlignErrors) )
if ! SNMPOUT=( $($LIBEXEC -v $SNMPV -c $SNMPC $HOST $CRC_MIB) ); then
	SETUNKNOWNCRC=1
fi

# now lets cut the snmpwalk output to portnumbers and crc-errors 
for i in "${SNMPOUT[@]}"
do
# check if value is empty
	if [ -z $i ]
		then
			echo ""
		else
			ifarray+=( $(echo "$i" | awk -F. '{ print $2 }' | awk -F " " '{ print $1 }') )
			crcarrayB+=( $(echo "$i" | awk -F " " '{ print $4 }' | tr -dc '0-9') )
	fi
done
for s in "${crcarrayB[@]-0}"
do
	crcarray+=( $(echo "$s") )
done
#now go over the array - here happens the magic
for i in ${ifarray[@]}
do
	if [ ${crcarray[i]-0} -ge "$CRIT" ]; then
		if [ $DEBUG -eq 1 ]; then
		echo "[DEBUG] CRIT THRESHOLD found: "${crcarray[i]} "CRC-Errors on Port: "${ifarray[i]}
		fi
                SETCRITCRC=1
                CRCPORTSCRIT+="Port ${ifparray[i]} (ID: ${ifarray[i]}) has ${crcarray[i]} CRC-ERRORS \n"
        elif [ ${crcarray[i]-0} -ge "$WARN" -a ${crcarray[i]-0} -lt "$CRIT" ]; then
		if [ $DEBUG -eq 1 ]; then
		echo "[DEBUG] WARN THRESHOLD found: "${crcarray[i]} "CRC-Errors on Port: "${ifarray[i]}
		fi
		SETWARNCRC=1
		CRCPORTSWARN+="Port ${ifparray[i]} (ID: ${ifarray[i]}) has ${crcarray[i]} CRC-ERRORS \n"
	fi

	#here we create the performance data
	CRCPERF+="Port ${ifarray[i]}=${crcarray[i]};$WARN;$CRIT;; "
done
# Output the CRC errors
if [ $SETUNKNOWNCRC -eq 1 ]; then
	echo "UNKNOWN"
	RETURN=3
elif [ $SETCRITCRC -eq 0 -a $SETWARNCRC -eq 0 -a $SETUNKNOWNCRC -eq 0 ]; then
	if [ $PERFDATA -eq 1 ]; then
		#OutputCRC
		echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
		echo "Model: $SYSMODEL"
		echo ""
		echo "OK - Switch has no CRC-Errors | $CRCPERF"
		RETURN=0
	else
		#OutputCRC
		echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
		echo "Model: $SYSMODEL"
		echo ""
		echo "OK - Switch has no CRC-Errors"
		RETURN=0
	fi
elif [ $SETCRITCRC -eq 1 ]; then
	if [ $PERFDATA -eq 1 ]; then
		#OutputCRC
		echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
		echo "Model: $SYSMODEL"
		echo ""
		echo "CRITICAL - $CRCPORTSCRIT | $CRCPERF"
		RETURN=2
	else
		#OutputCRC
		echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
		echo "Model: $SYSMODEL"
		echo ""
		echo "CRITICAL - $CRCPORTSCRIT"
		RETURN=2
	fi
elif [ $SETWARNCRC -eq 1 ] &&  [ $SETCRITCRC -eq 0 ]; then
	if [ $PERFDATA -eq 1 ]; then
			#OutputCRC
			echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
			echo "Model: $SYSMODEL"
			echo ""
        	echo "WARNING - $CRCPORTSWARN | $CRCPERF"
		RETURN=1
	else
		#OutputCRC
		echo "$SYSNAME in $SYSLOCATION has Version: $SYSDESC"
		echo "Model: $SYSMODEL"
		echo ""
		echo "WARNING - $CRCPORTSWARN"
		RETURN=1
	fi
fi

unset IFS
}

#########################################################
# Check for Packet-Errors
#########################################################
function getInterfacesPacketInErrors {

IFS=$'\n'   #set separator to newline only

#some local variables
IF_PORT_IN=""
IF_PORT_IN_ERRORS=0
ERRORS_ENTIRE=""

#get informations from snmpwalk
############################################################
if ! SNMPOUTPUT_IN=( $($LIBEXEC -v $SNMPV -c $SNMPC $HOST $IF_MIB_IN_ERRORS) ); then
	SETUNKNOWNP=1
fi

# iterate port numbers & error pakets for incoming packets
for ii in ${SNMPOUTPUT_IN[@]}
do
        IF_PORT_IN=( $(echo "$ii" | awk -F "." '{ print $11 }' | awk -F " " '{ print $1 }' ) )
        IF_PORT_IN_ERRORS=( $(echo "$ii" | awk -F " " '{ print $4 }') )
		ii_desc=( $(echo "$ii" | cut -d " " -f4) )
		ifportarray+=($IF_PORT_IN)
		#echo "${ifportarray[9]}"
		
        if [ $IF_PORT_IN_ERRORS -gt $WARN -a  $IF_PORT_IN_ERRORS -lt $CRIT ]; then
		if [ $DEBUG -eq 1 ]; then
			echo "[DEBUG] WARNING Threshold $IF_PORT_IN_ERRORS found on Port $IF_PORT_IN"
		fi
                PORT_IN_ERROR_WARN+="Port $IF_PORT_IN has $IF_PORT_IN_ERRORS incoming Packet-Errors "
                SETWARNP=1
        elif [ $IF_PORT_IN_ERRORS -gt $CRIT ]; then
		if [ $DEBUG -eq 1 ]; then
                        echo "[DEBUG] CRITICAL Threshold $IF_PORT_IN_ERRORS found on Port $IF_PORT_IN"
                fi
                PORT_IN_ERROR_CRIT+="Port $IF_PORT_IN has $IF_PORT_IN_ERRORS incoming Packet-Errors "
                SETCRITP=1
        fi

	#here we create the performance data
        PACKETPERF+="Port $IF_PORT_IN=$IF_PORT_IN_ERRORS;$WARN;$CRIT;; "
done

# OUTPUT-MESSAGES  for incoming packet errors
if [ $SETUNKNOWNP -eq 1 ]; then
        echo "UNKNOWN"
		RETURNPIN=3
elif [ $SETCRITP -eq 0 -a $SETWARNP -eq 0 -a $SETUNKNOWNP -eq 0 ]; then
        if [ $PERFDATA -eq 1 ]; then
                echo "OK - Switch has no incoming Packet-Errors | $PACKETPERF"
				RETURNPIN=0
        else
                echo "OK - Switch has no incoming Packet-Errors"
				RETURNPIN=0
        fi
elif [ $SETCRITP -eq 1 ]; then
        if [ $PERFDATA -eq 1 ]; then
                echo "CRITICAL - $PORT_IN_ERROR_CRIT | $PACKETPERF"
				RETURNPIN=2
        else
                echo "CRITICAL -  $PORT_IN_ERROR_CRIT"
				RETURNPIN=2
        fi
elif [ $SETWARNP -eq 1 ] &&  [ $SETCRITP -eq 0 ]; then
        if [ $PERFDATA -eq 1 ]; then
                echo "WARNING - $PORT_IN_ERROR_WARN | $PACKETPERF"
				RETURNPIN=1
        else
                echo "WARNING - $PORT_IN_ERROR_WARN"
				RETURNPIN=1
        fi
fi
unset IFS

}

function getInterfacesPacketOutErrors {

IFS=$'\n'   #set separator to newline only

#some local variables
IF_PORT_IN_OUT=""
IF_PORT_IN_ERRORS_OUT=0
IF_PORT_OUT_ERRORS=0
ERRORS_ENTIRE=""

#get informations from snmpwalk
SNMPOUTPUT_OUT+=( $($LIBEXEC -v $SNMPV -c $SNMPC $HOST $IF_MIB_OUT_ERRORS) )

# iterate port numbers & error pakets for outgoing packets
for io in ${SNMPOUTPUT_OUT[@]}
do
        IF_PORT_IN_OUT=( $(echo "$io" | awk -F "." '{ print $11 }' | awk -F " " '{ print $1 }' ) )
        IF_PORT_IN_ERRORS_OUT=( $(echo "$io" | awk -F " " '{ print $4 }') )

        if [ $IF_PORT_IN_ERRORS_OUT -gt $WARN -a  $IF_PORT_IN_ERRORS_OUT -lt $CRIT ]; then
		if [ $DEBUG -eq 1 ]; then
			echo "[DEBUG] WARNING Threshold $IF_PORT_IN_ERRORS_OUT found on Port $IF_PORT_IN_OUT"
		fi
				p=$( echo "$IF_PORT_IN_OUT" )
                PORT_IN_ERROR_WARN_OUT+="Port $IF_PORT_IN_OUT has $IF_PORT_IN_ERRORS_OUT outgoing Packet-Errors  \n"
                SETWARNP_OUT=1
        elif [ $IF_PORT_IN_ERRORS_OUT -gt $CRIT ]; then
		if [ $DEBUG -eq 1 ]; then
                        echo "[DEBUG] CRITICAL Threshold $IF_PORT_IN_ERRORS_OUT found on Port $IF_PORT_IN_OUT"
                fi
				p=$( echo "$IF_PORT_IN_OUT" )
                PORT_IN_ERROR_CRIT_OUT+="Port $IF_PORT_IN_OUT has $IF_PORT_IN_ERRORS_OUT outgoing Packet-Errors  \n"
                SETCRITP_OUT=1
        fi

	#here we create the performance data
        PACKETPERF_OUT+="Port $IF_PORT_IN_OUT=$IF_PORT_IN_ERRORS_OUT;$WARN;$CRIT;; "
done
# OUTPUT-MESSAGES for outgoing packet errors
if [ $SETUNKNOWNP_OUT -eq 1 ]; then
        echo "UNKNOWN"
        RETURNPOUT=3
elif [ $SETCRITP_OUT -eq 0 -a $SETWARNP_OUT -eq 0 -a $SETUNKNOWNP_OUT -eq 0 ]; then
        if [ $PERFDATA_OUT -eq 1 ]; then
                echo "OK - Switch has no outgoing Packet-Errors | $PACKETPERF_OUT"
                RETURNPOUT=0
        else
                echo "OK - Switch has no outgoing Packet-Errors "
                RETURNPOUT=0
        fi
elif [ $SETCRITP_OUT -eq 1 ]; then
        if [ $PERFDATA_OUT -eq 1 ]; then
				echo "CRITICAL - $PORT_IN_ERROR_CRIT_OUT | $PACKETPERF_OUT"
                RETURNPOUT=2
        else
				echo "CRITICAL -  $PORT_IN_ERROR_CRIT_OUT"
                RETURNPOUT=2
        fi
elif [ $SETWARNP_OUT -eq 1 ] &&  [ $SETCRITP -eq 0 ]; then
        if [ $PERFDATA_OUT -eq 1 ]; then
				echo "WARNING - $PORT_IN_ERROR_WARN_OUT | $PACKETPERF_OUT"
                RETURNPOUT=1
        else
				echo "WARNING - $PORT_IN_ERROR_WARN_OUT"
                RETURNPOUT=1
        fi
fi

unset IFS

}

# Output the correct Return code, analyse all 3 return values and select the highest
function setReturnCode {

if [ $RETURN -eq 0 ] && [ $RETURNPIN -eq 0 ] && [ $RETURNPOUT -eq 0 ]; then
	RETURN=0
elif [ $RETURN -eq 1 ] || [ $RETURNPIN -eq 1 ] || [ $RETURNPOUT -eq 1 ]; then
	RETURN=1
elif [ $RETURN -eq 2 ] || [ $RETURNPIN -eq 2 ] || [ $RETURNPOUT -eq 2 ]; then
	RETURN=2
elif [ $RETURN -eq 3 ] || [ $RETURNPIN -eq 3 ] || [ $RETURNPOUT -eq 3 ]; then
	RETURN=3
fi

}

main() {

if [ -z $HOST ]; then
	print_help
else
	getSwitchInfo
	getPortDesc
	#echo "CRC Errors:"
	getInterfacesCRCErrors
	echo "Incoming Packet Errors:"
	getInterfacesPacketInErrors
	echo ""
	echo "Outgoing Packet Errors:"
	getInterfacesPacketOutErrors
	setReturnCode
fi

if [ $DEBUG -eq 1 ]; then
echo "[Return Code] = $RETURN"
fi
exit $RETURN
}

main "$@"

