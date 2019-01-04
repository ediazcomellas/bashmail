#!/bin/bash

#This script sends an email using as little dependencies as possible
#Copyright (C) 2019 Eduardo Diaz Comellas - ediaz@ultreia.es
#
#This program is free software: you can redistribute it and/or modify it 
#under the terms of the GNU General Public License as published by the 
#Free Software Foundation, either version 3 of the License, or (at your 
#option) any later version.
#
#This program is distributed in the hope that it will be useful, but 
#WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
#or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
#for more details.
#
#You should have received a copy of the GNU General Public License 
#along with this program. If not, see http://www.gnu.org/licenses/.

# Several ideas taken from dldnh at 
#https://stackoverflow.com/questions/9998710/is-it-possible-to-send-mails-by-bash-script-via-smtp


#Customize smtp server, protocol, port, login and password.
#Server to use as MTA
SMTPSERVER=my.mail.server.com
#Port (can be left blank and will be deduced). We rather use 587 for submission,
#as 25 is usually firewalled
SMTPPORT=
#USESSL=1 -> send using SSL, USESSL=2 -> send with STARTTLS
#USESSL=0 -> no encryption... beware that password will be sent in plaintext
#If USESSL is different to [012], will use no encryption and default to port 25
USESSL=2
#Auth type to use, can be login, plain or none. If left empty, "none" is selected
USEAUTH=login
#Login and password to use
LOGIN=mylogincredential
PASSWORD=mypassword
#How much seconds to wait for an SMTP answer from the server
#Beware that a value under 5 may cause timeouts in normal operation
SMTPTIMEOUT=10
#How will we identify ourselves at the HELO time. Leave empty for system hostname
HELOHOSTNAME=
#Optional openssl command modifiers
OPENSSLOPTIONS=""


#Now we try to discover several variables if they are not previously declared
#No modifications below this line should be neccesary . Jump to the section 
#called #MYEMAILMESSAGEHERE

#Deduce hostname, if not previously set
DHELOHOSTNAME=${HELOHOSTNAME:-$(hostname)}

#Set a default for USESSL (SSL, port 465)
DUSESSL=${USESSL:-1}

#Provide a SMTPPORT, if empty
if [ -z $SMTPPORT ]
then
   case $DUSESSL in
   0)
      SMTPPORT=587
      ;;
   1)
      SMTPPORT=465
      ;;
   2)
      SMTPPORT=587
      OPENSSLOPTIONS="-starttls smtp $OPENSSLOPTIONS "
      ;;
   *)
      echo >&2 "Warning: USESSL has unrecognized value. Defaulting to port 25 and no encryption"
      SMTPPORT=25
      ;;
   esac
fi 

if [ $SMTPPORT -eq 25 ]
then
      echo >&2 "Warning: using port 25 can be problematic. Consider 587"
fi

if [ -z $USEAUTH ]
then
	USEAUTH=none
elif [ $USEAUTH != "none" -a $USEAUTH != "login" -a $USEAUTH != "plain" ]
then
	echo >&2 "ERROR: Unrecognized value for USEAUTH. Please set it to none, plain or login"
	exit 1
fi


#Make sure we have an SMTPTIMEOUT value
DSMTPTIMEOUT=${SMTPTIMEOUT:-4}

# Check that we have cut and grep. Should be in any sensible UNIX-like system anyway
hash cut 2>/dev/null || { echo >&2 "ERROR: cut command is required but not available. Aborting."; exit 1; }
hash grep 2>/dev/null || { echo >&2 "ERROR: grep command is required but not available. Aborting."; exit 1; }

# Check if we have base64 (needed for auth)
if [ $USEAUTH == "plain" -o $USEAUTH == "login" ]
then
      hash base64 2>/dev/null || { echo >&2 "ERROR: base64 command is required but not available. Aborting."; exit 1; }
fi

#Some other things needed if we use ssl
if [ $USESSL -eq 1 -o $USESSL -eq 2 ]
then
      hash openssl 2>/dev/null || { echo >&2 "ERROR: Encryption required but openssl is not available. Aborting."; exit 1; }
      hash mkfifo 2>/dev/null || { echo >&2 "ERROR: mkfifo command is required but not available. Aborting."; exit 1; }
      hash mktemp 2>/dev/null || { echo >&2 "ERROR: mktemp command is required but not available. Aborting."; exit 1; }
fi



#Function used to check the SMTP status
function checkStatus {
  #echo call: checkStatus $1 $2 
  expect=250
  code=`echo $1 | cut -d- -f1`
  line=$2
  numparams=$#
  if [ $numparams -eq 3 ] ; then
    expect="${3}"
  else 
    if [ $numparams -ne 2 ] ; then
	    echo >&2 "Error on call to checkStatus. Incorrect number of parameters $#"
	    exit 2
    fi
  fi	
  if [ -z $code ]
  then
	  echo >&2 "Error: was expecting ${expect} but received blank. ${1} ${2}"
	  exit 2
  elif [ $code -ne $expect ]
  then
	  echo >&2  "Error: was expecting ${expect} but received ${1}:  ${2}"
    	  exit 2
  fi
}

#Where all the magic happens
bashmail () {
    from_addr="$1"
    to_addr="$2"
    cc_addr="$3"
    subject="$4"
    body="$5"
    #This vars are initialized at the top of the script
    myhostname=$DHELOHOSTNAME
    smtpserver=$SMTPSERVER
    smtpport=$SMTPPORT
    ssl=$USESSL
    auth=$USEAUTH
    username=$LOGIN
    password=$PASSWORD
    timeout=$DSMTPTIMEOUT


    #Flag initialization. Dont modify
    loginsupported=0
    authsupported=0
 

    if [ $ssl -eq 1 -o $ssl -eq 2 ]
    then
       FIFODIR=`mktemp -d`
       mkfifo ${FIFODIR}/sto
       mkfifo ${FIFODIR}/ots
       #This has to be in background
       openssl s_client -connect ${smtpserver}:${smtpport} ${OPENSSLOPTIONS} -ign_eof  -quiet -verify_quiet >& ${FIFODIR}/ots < ${FIFODIR}/sto &
       #This is tricky... dont change order
       exec 4< ${FIFODIR}/ots
       exec 3> ${FIFODIR}/sto
       OUTFD=3
       INFD=4
    else
       exec 3<>/dev/tcp/${smtpserver}/${smtpport}
       OUTFD=3
       INFD=3
    fi

    read -t ${timeout} -u ${INFD} line
    #If using openssl and connection fails, an error line is captured
    echo $line | grep -i error  > /dev/null
    if [ $? -eq 0 ]
    then
	    echo >&2 "ERROR: Connection to ${smtpserver}:${smtpport} failed"
	    exit 4
    fi

    #checkStatus "$sts" "$line" 220

    echo "EHLO ${myhostname}" >&${OUTFD}

    read -t ${timeout} -u ${INFD} sts line
    checkStatus "$sts" "$line"

    SAL=0
    while [ $SAL -eq 0 ]
    do
	#We are going to read all the remainder lines, one at a time
	#until it timeouts (1sec)
	read -u ${INFD}  -t 1 linea
	SAL=$?
	#Check if auth login is supported
	echo $linea |grep -i auth | grep -i login > /dev/null
	if [ $? -eq 0 ]; then
		loginsupported=1
	fi
	echo $linea |grep -i auth | grep -i plain > /dev/null
	if [ $? -eq 0 ]; then
		plainsupported=1
	fi
    done

    if [ ${auth} == "login" ]
    then
	    if [ ${loginsupported} -ne 1 ]
	    then
		    echo >&2 "ERROR: AUTH LOGIN requested, but not advertised"
		    exit 3
	    fi
	    #echo "Voy a autenticarme ${sts} ${line}"
	    userB64=`echo -ne ${username} | base64`
	    passB64=`echo -ne ${password} | base64`
	    echo "AUTH LOGIN" >&${OUTFD}
	    read -t ${timeout} -u ${INFD} sts line
	    checkStatus "$sts" "$line" 334
	    echo ${userB64} >&${OUTFD}
	    read -t ${timeout} -u ${INFD} sts line
	    checkStatus "$sts" "$line" 334
	    echo ${passB64} >&${OUTFD}
	    read -t ${timeout} -u ${INFD} sts line
	    checkStatus "$sts" "$line" 235
    elif [ ${auth} == "plain" ]
    then
	    if [ ${plainsupported} -ne 1 ]
	    then
		    echo >&2 "ERROR: PLAIN LOGIN requested, but not advertised"
		    exit 3
	    fi
	    #echo "Voy a autenticarme ${sts} ${line}"
	    userpassB64=`echo -ne "\0${username}\0${password}" | base64`
	    echo "AUTH PLAIN ${userpassB64}" >&${OUTFD}
	    read -t ${timeout} -u ${INFD} sts line
	    checkStatus "$sts" "$line" 235

    fi

    echo "MAIL FROM: ${from_addr}" >&${OUTFD}

    read -t ${timeout} -u ${INFD} sts line
    checkStatus "$sts" "$line"

    echo "RCPT TO: ${to_addr}" >&${OUTFD}

    read -t ${timeout} -u ${INFD} sts line
    checkStatus "$sts" "$line"

    echo "DATA" >&${OUTFD}

    read -t ${timeout} -u ${INFD} sts line
    checkStatus "$sts" "$line" 354

    echo "Subject: ${subject}" >&${OUTFD}
    echo "" >&${OUTFD}
    echo "${body}" >&${OUTFD}
    echo "." >&${OUTFD}

    read -t ${timeout} -u ${INFD} sts line
    checkStatus "$sts" "$line"
   
    #Clean up and go home
    exec {OUTFD}>&-
    if [ $ssl -eq 1 -o $ssl -eq 2 ]
    then
    	exec {INFD}<&-
	rm ${FIFODIR}/sto ${FIFODIR}/ots
	rm -d  ${FIFODIR}
    fi
}

#MYEMAILMESSAGEHERE
#The sintax is: bashmail from to cc subject body

bashmail "ultreia@froiz.es" "ediaz@ultreia.es" "" "Mail de prueba: `date`" "En un lugar de la mancha
de cuyo nombre no quiero acordarme
no ha mucho tiempo ...."


