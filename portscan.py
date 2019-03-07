#CSCI 5742
#Cybersecurity Programming
#Final Project
#Portscanner interface with CVE
#Jonathan Trejo and Matt Sullivan
#11/27/2018
#portscan.py

import os
import socket

def runportscan(hostname, startport, endport):

    startport = int(startport)
    endport = int(endport)

    stringresult = ""

    socket.setdefaulttimeout(.01)  # Speeds up the socket scanning speed
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    for x in range(startport,endport):
        addtoCounter=0
        result = sock.connect_ex((hostname, x))
        if result == 0:
            stringresult += str("Port "+ str(x) + " is open")
            addtoCounter=1




    return stringresult, addtoCounter
