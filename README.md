# bashmail
Bash script to send emails using SMTP with minimal dependencies.

This script can be used to send emails through an STMP server from 
simple UNIX servers. It supports authentication (LOGIN and PLAIN), 
and encryption SSL and STARTTLS. 

I've tried to make it as portable as possible, with minimal requirements.
For simplest use cases (only sending email, with no SSL nor AUTH), only
bash, grep and cut are needed. 

Customization
-------------

Edit variables at the top of the script and change the email at the bottom. 
All variables are explained inline. 

I hope you find it useful. 
