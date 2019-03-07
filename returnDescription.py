#CSCI 5742
#Cybersecurity Programming
#Final Project
#Portscanner interface with CVE
#Jonathan Trejo and Matt Sullivan
#11/27/2018
#returnDescription.py


import csv

def returnDescription(input):       #Function to return description from the CVE database
    listOut=[]      #List of vulnerabilities that match the keywords
    stringout=''    #message to user
    URL=''          #URL storage
    line_count=0
    with open('allitems.csv', 'r', errors='ignore') as csv_file:    #opens as a csv file
        next(csv_file)      #skips the first few lines
        next(csv_file)
        csv_read = csv.DictReader(csv_file) #opens as a csv dictionary
        for row in csv_read:            #steps through csv dictionary
            for entry in input:         #steps through the input file
                if entry in row["Description"]:     #if the keyword is in the description
                    getURL=row["References"].split("|")     #working variable for URL storage
                    for refs in getURL:                     #finds the URL in the CVE file
                        if "URL:" in refs:
                            URL=refs[7:-3]
                    listOut.append(row["Name"] +"| " + row["Description"]+"| "+URL)     #puts name, description and URL and appends to list
                    line_count += 1
    stringout ="Returned " + str(line_count) + " potential vulnerabilities."        #message for user
    if line_count == 0:
        stringout = "No Matches found"
    return stringout, listOut   #returns the message to user and the list of vulnerabilities
