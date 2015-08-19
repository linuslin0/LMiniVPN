#LMiniVPN - Linux Mini VPN

This is a simple Linux VPN using TUN device.

#Usage:

Server:

./DVServer -d

Client:

./DVClient -c PKILabServer.com -d

PKILabServer.com is the example domain used to setup the SSL certificate.

Test certificates included.

Test login:

Username: user

Password: user

Control command can be used in the console:

To change a new encryption key:

-newkey

To abort the connection to the server:

-abort

