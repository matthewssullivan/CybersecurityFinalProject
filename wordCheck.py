#CSCI 5742
#Cybersecurity Programming
#Final Project
#Portscanner interface with CVE
#Jonathan Trejo and Matt Sullivan
#11/27/2018
#wordCheck.py


import string

def wordCheck(searchWord):                      #Function to check a word list against a dictionary and remove words that are in the dictionary
    file = open("wordlist.txt")                 #dictionary retrieved online
    words = file.read()                         #reads into variable
    for item in words:
        item = item.lower()                     #converts all letters to lowercase for spell checking

    searchWord=searchWord.split()
    refinedList=[]

    for word in searchWord:
        testword = word.lower()+"\n"        #adds a newline to the end of the word being tested because the dictionary is newline deliniated
        if testword not in words:
            refinedList.append(word+" ")    #adds a space because the strings we will be comparing the results to are whitespace deliniated
    file.close()

    return refinedList
