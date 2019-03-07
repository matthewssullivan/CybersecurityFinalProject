#CSCI 5742
#Cybersecurity Programming
#Final Project
#Portscanner interface with CVE
#Jonathan Trejo and Matt Sullivan
#11/27/2018
#returnPortDescription.py

import csv

def returnPortDescription(portNum):                     #function to return the description from the list of ports
    with open("service-names-port-numbers (1).csv", mode = 'r') as f:   #opens the file
        csvDict=csv.DictReader(f)                                       #reads it in as a dictionary
        for row in csvDict:         #step through the file
            workNums=row["Port Number"].split("-")      #checks if it's a range
            if len(workNums) <2:                        #if it is not
                if portNum == int(row["Port Number"]):  #return the description
                    return row["Description"]
            else:                                                   #if it is a range
                if int(workNums[0]) <= portNum <= int(workNums[1]): #check and see if it's in range
                    return row["Description"]                       #return the description
    f.close()
