# drown
Implementation of the special DROWN attack on SSL2

Note : this does not cover the general DROWN attack.


## Passive attack

In this type of attack, we can see the traffic between a server and a client using TLS.
In this case, we can decrypt some TLS sessions if :
* the same server, or another server, allows SSLv2 connections with the same public key ;
* the TLS sessions uses RSA as a key exchange algorithm (no Diffie-Hellman) ;
* the server is vulnerable to CVE-2016-0800 ;
* there is a sufficient number of session.

## Simulation

To simulate this scenario, we must install an old version of OpenSSL :

    wget https://www.openssl.org/source/openssl-1.0.1l.tar.gz
    tar xzf openssl-1.0.1l.tar.gz
    cd openssl-1.0.1l
    ./config enable-ssl2 enable-weak-ciphers --openssldir=/path/to/prefix
    make && make install
    cd /path/to/prefix

Now, we want to record some TLS sessions. We will create a server, launch tshark to capture the packets, and initiate a lot of sessions.

    ./bin/openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 123
    ./bin/openssl s_server -cert cert.pem -key key.pem -accept 4433 -www
    tshark -i lo -w handshakes.cap
    for i in $(seq 1000) ; do (echo 'GET / HTTP/1.1\r\n'; sleep 0.1) | ./bin/openssl s_client -connect 127.0.0.1:4433 -cipher kRSA; done

We can now get the encrypted pre-master secrets for each session with :

    tshark -r handshakes.cap -d tcp.port==4433,ssl -T fields -e ssl.handshake.epms -Y ssl.handshake.epms | tr -d :

Now we must decrypt these handshakes (to be continued...).
