#!/usr/bin/python
# -*- coding: utf-8 -*-
 
# The modules required
from http import server
import math
import secrets
import sys
import socket
import struct
import os


'''
Introduction to Internet 2022 coursework by Jaakko Astikainen.

Command line argument message should be "HELLO ENC MUL PAR" with the quote marks
'''
 
def send_and_receive_tcp(address, port, message):
    print("You gave arguments: {} {} {}".format(address, port, message))
    # create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect socket to given address and port
    s.connect((address, port))

    # create encryption keys
    keys = create_keys(20)
    if "ENC" in message:
        message = message + "\r\n"
        for key in keys:
            message = message + key + "\r\n"
        message = message + ".\r\n"
    else:
        message = message + "\r\n"


    print("Sent message:\n" + message)
    # python3 sendall() requires bytes like object. encode the message with str.encode() command
    msg_bytes = message.encode()

    # send given message to socket
    s.sendall(msg_bytes)

    # receive data from socket
    data_bytes = s.recv(2048)

    # data you received is in bytes format. turn it to string with .decode() command
    data = data_bytes.decode()

    # print received data
    print("Received message:\n" + data)

    # close the socket
    s.close()

    # Get your CID and UDP port from the message
    if "ENC" in message:
        data_split = data.split("\r\n")
        cid_port = data_split[0].split(" ")
        cid = cid_port[1]
        udp_port = cid_port[2]
        keys_recv = data_split[1:-2]
    else:
        data_split = data.split(" ")
        cid = data_split[1]
        udp_port = data_split[2]
        #if no encryption, just fill received keys with generated keys so function works later
        keys_recv = keys

    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, udp_port, cid, message, keys, keys_recv)

    return
 
 
def send_and_receive_udp(address, port, cid, message, keys, keys_recv):

    # server address and port
    serverAddrPort = (address, int(port))

    # creating a UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if "ENC" in message:
        encrypt_key = keys.pop(0)

    # forming the starting message to send
    msg = "Hello from " + cid + "\n"
    old_msg = msg
    if "ENC" in message:
        msg = encrypt_message(msg, encrypt_key)
    cont_len = len(msg)
    if "PAR" in message:
        msg_par = ""
        for i in range(0, len(msg)):
            msg_par = msg_par + add_parity(msg[i])
        msg = msg_par

    msg_bytes = msg.encode()

    # UDP messaging variables
    cid_bytes = cid.encode()
    ack_bool = True
    eom_bool = False
    data_rem = 0
    bufferSize = 1024

    # packing the message
    Data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, cont_len, msg_bytes)

    # send the first message of the UDP interaction
    s.sendto(Data, serverAddrPort)
    if "PAR" in message:
        msg = string_rm_parity(msg)
    print("Message\n" + old_msg + "sent to " + str(address) + ":" + str(port) + "\n")

    # start the messaging
    while (True):
        #receive and unpack message
        Data_recv = s.recvfrom(bufferSize)
        cid, ack_bool, eom_bool, data_rem, recv_len, recv_bytes = struct.unpack('!8s??HH128s', Data_recv[0])

        #msg_recv = recv_bytes.decode()


        # check EOM bit
        if eom_bool is True:
            break
        
        if "MUL" in message and data_rem != 0:
            tot_msg = recv_bytes.decode()
            total_len = recv_len
            tmp_string = tot_msg
            tmp_string = tmp_string[0:recv_len]
            tot_msg = tmp_string
            while(True):
                Data_recv = s.recvfrom(bufferSize)
                cid, ack_bool, eom_bool, data_rem, recv_len, recv_bytes = struct.unpack('!8s??HH128s', Data_recv[0])
                tmp_string = recv_bytes.decode()
                tmp_string = tmp_string[0:recv_len]
                tot_msg = tot_msg + tmp_string
                total_len += recv_len
                if data_rem == 0:
                    break
            recv_bytes = tot_msg.encode()
            recv_len = total_len
            #print(recv_len)


        # decode and reverse the word list, check parity and decrypt message
        msg_recv = recv_bytes.decode()
        #print(msg_recv)
        if "PAR" in message:
            for char in msg_recv:
                parity_ok = check_parity(char)
                if parity_ok is False:
                    ack_bool = False
            #remove parity from the message since it makes it into a character salad
            msg_recv = string_rm_parity(msg_recv)

        #if NAK, resend package
        if ack_bool is False and data_rem == 0:
            #discard the wasted decryption keys
            keys_recv = keys_recv[math.ceil(recv_len/64):]
            error_msg = "Send again"
            error_len = len(error_msg)
            if "ENC" in message and len(keys) != 0:
                try:
                    encrypt_key = keys.pop(0)
                    error_msg = encrypt_message(error_msg, encrypt_key)
                except IndexError:
                    print("All encryption keys used")
            error_msg = error_msg.encode()
            flaw_data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, error_len, error_msg)
            s.sendto(flaw_data, serverAddrPort)
            print("Parity check failed, sent message: Send again" + " to " + str(address) + ":" + str(port) + "\n")
            continue

        msg_recv = msg_recv[0:recv_len]


        if "ENC" in message and len(keys_recv) != 0:
            if "MUL" in message:
                tmp_string = ""
                enc_pieces = split_message(msg_recv)
                for piece in enc_pieces:
                    try:
                        decrypt_key = keys_recv.pop(0)
                        tmp_string = tmp_string + encrypt_message(piece, decrypt_key)
                    except IndexError:
                        tmp_string = tmp_string + piece
                msg_recv = tmp_string
            else:
                decrypt_key = keys_recv.pop(0)
                msg_recv = encrypt_message(msg_recv, decrypt_key)


        print("Received message: " + msg_recv + "\n")
        word_list = msg_recv.split(" ")
        msg_send = word_list[::-1]
        msg_send = " ".join(msg_send)
        print("Reversed word list: " + msg_send + "\n")


        # NAK message was here

        # prepare message for sending
        if "MUL" in message:
            pieces = split_message(msg_send)
        else:
            pieces = msg_send
        #print(pieces)
        data_rem = len(msg_send)

        for piece in pieces:
            
            msg_send = piece
            cont_len = len(msg_send)
            data_rem -= cont_len

            if "ENC" in message and len(keys) != 0:
                try:
                    encrypt_key = keys.pop(0)
                    msg_send = encrypt_message(msg_send, encrypt_key)
                except IndexError:
                    print("All encrypt keys used")
            
            if "PAR" in message:
                msg_send_par = ""
                for i in range(0,len(msg_send)):
                    msg_send_par = msg_send_par + add_parity(msg_send[i])
                msg_send = msg_send_par

            msg_bytes = msg_send.encode()
            #print(data_rem)
            Data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, cont_len, msg_bytes)
            s.sendto(Data, serverAddrPort)
            
        print("Message sent to " + str(address) + ":" + str(port) + "\n\n------------------")
            
    
    # program jumps here after EOM bit = 1
    last_msg = recv_bytes.decode()
    print("Received message: " + last_msg)

    s.close()

    return
 
def create_keys(amount):
    key_array = []
    for i in range(0,amount):
        key = secrets.token_hex(32)
        key_array.append(key)

    return key_array

def encrypt_message(message, key):
    #key_str = str.decode(key)
    encrypted = str("")
    for i in range(0,len(message)):
        encrypted = encrypted + (chr(ord(message[i]) ^ ord(key[i])))

    return encrypted

def get_parity(n):
    while n > 1:
        n = (n >> 1) ^ (n & 1)
    return n

def add_parity(c):
    c = ord(c)
    c <<= 1
    c += get_parity(c)
    c = chr(c)
    return c

def check_parity(a):
    a = ord(a)
    parity_bit = a & 1
    a >>= 1
    test_parity = get_parity(a)

    if parity_bit == test_parity:
        return True
    else:
        return False

def string_rm_parity(string):
    rm_string = ""
    for c in string:
        a = ord(c)
        a >>= 1
        a = chr(a)
        rm_string = rm_string + a
    return rm_string

def split_message(message):
    return [message[i:i+64] for i in range(0, len(message), 64)]


def main():
    USAGE = 'usage: %s <server address> <server port> <message>' % sys.argv[0]
 
    try:
        # Get the server address, port and message from command line arguments
        server_address = str(sys.argv[1])
        server_tcpport = int(sys.argv[2])
        message = str(sys.argv[3])
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
    # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)
 
    send_and_receive_tcp(server_address, server_tcpport, message)
 
 
if __name__ == '__main__':
    # Call the main function when this script is executed
    main()
