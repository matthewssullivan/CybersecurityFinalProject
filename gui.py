#CSCI 5742
#Cybersecurity Programming
#Final Project
#Portscanner interface with CVE
#Jonathan Trejo and Matt Sullivan
#11/27/2018
#gui.py

import os
from tkinter import *
from tkinter import Menu
from tkinter import ttk
import webbrowser
import tkinter.messagebox
import wordCheck
import returnDescription
import returnPortDescription

from tkinter.ttk import Progressbar

import portscan

class gui(object):                  #GUI class

    # set up main page
    def __init__(self, master):
        self.master = master
        master.title("Jon T & Matt S - Advanced Port Scanner")

        self.statusVar = StringVar()  # Variable to store status bar messsage
        self.statusVar.set("Ready")  # Set status bar message

        self.frame3=Frame(self.master)          #frame for the status bar
        self.frame3.pack(side=BOTTOM, fill=X)

        self.frame1=Frame(self.master)          #left side frame
        self.frame1.pack(side=LEFT, fill=X)

        self.frame2=Frame(self.master)          #right side frame
        self.frame2.pack(side=LEFT, fill=X)


        # *********StatusBar************
        self.status = Label(self.frame3, text=self.statusVar.get(), bd=1, relief=SUNKEN,anchor=W)  # Cool looking dynamic status bar
        self.status.pack(side=BOTTOM, fill=X)  # stuck to the bottom

        # *****menu setup*****
        self.dropDown = Menu(master)  # starts out dropdown menu
        master.config(menu=self.dropDown)
        self.fileMenu = Menu(self.dropDown, tearoff=False)
        self.dropDown.add_cascade(label="File", menu=self.fileMenu)  # Adds File submenu
        self.fileMenu.add_command(label="New", command=self.clearData)  # Adds New to file
        self.fileMenu.add_separator()  # Makes it pretty
        self.fileMenu.add_command(label="Exit", command=master.quit)  # Adds a quit function

        self.helpMenu = Menu(self.dropDown, tearoff=False)  # Creates a help submenu
        self.dropDown.add_cascade(label="Help", menu=self.helpMenu)  # adds menu options
        self.helpMenu.add_command(label="About", command=self.signature)


        #create tabs
        self.tab_control = ttk.Notebook(self.master)        #Tabs allow future functionality expansion potential
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab1, text="Port Scanner")
        self.tab_control.pack(expand=1, fill="both")

        # text box label
        self.label1=Label(self.frame1,text='Enter IP Address')
        self.label2=Label(self.frame1,text='Enter start port')
        self.label3=Label(self.frame1,text='Enter end port')

        self.label1.grid(row=4,column=0)
        self.label2.grid(row=5,column=0)
        self.label3.grid(row=6,column=0)

        # text box
        self.entry1=Entry(self.frame1)
        self.entry2=Entry(self.frame1)
        self.entry3=Entry(self.frame1)

        self.entry1.grid(row=4, column=1)
        self.entry2.grid(row=5, column=1)
        self.entry3.grid(row=6, column=1)

        # text area box
        self.openPorts=Listbox(self.tab1)
        self.openPorts.pack(expand=1, fill="both")

        #setup for port info
        self.openPorts.bind("<Double-Button-1>", self.portinfo) #double clicking launches the functions to gather info


        self.statusText=Listbox(self.frame1)            #Status updates for user
        self.statusText.grid(row=8, stick=N+S+E+W, columnspan=2)

        self.statusScroll=Scrollbar(self.frame1, orient="vertical")     #scroll through history of status updates
        self.statusScroll.grid(row=8,column=3,sticky=N+S+E)
        self.statusScroll.config(command=self.statusText.yview)

        # enter button
        self.btn = Button(self.frame1, text='Submit', command=lambda: self.runportscan(self.entry1.get(), self.entry2.get(), self.entry3.get()))
        master.bind('<Return>', lambda event: self.runportscan(self.entry1.get(), self.entry2.get(), self.entry3.get()))
        self.btn.grid(row=7,column=1)

        self.progressBar = tkinter.ttk.Progressbar(self.frame1, orient='horizontal', value=0, mode='determinate')   #dynamic progress bar
        self.progressBar.grid(row=12, stick=W+E, columnspan =2)

        self.progressUpdate=Label(self.frame1, text="0/0")      #dynamic text updates
        self.progressUpdate.grid(row=13, stick=W)


        # set window size
        self.master.geometry('650x600')

    def valueGET(self, val1, val2, val3):
        print(val1, val2, val3)

    def launchpPortInfo(self):
        string = self.openPorts.get(ACTIVE)
        selfinfo(string)
        return "break".port

    def portinfo(self, string):

        string = self.openPorts.get(ACTIVE)

        # where we save our result
        portinfo = ''
        vulnerabilityinfo = ''

        # get the out from the text line and save only the numbers(port) to x
        x = ''.join(c for c in string if c.isdigit())       #gets the port #
        portinfo=returnPortDescription.returnPortDescription(int(x))        #calls returnPortDescription function to return that port's description
        portwords = wordCheck.wordCheck(portinfo)   #uses wordCheck to check the words in the description and eliminate any that are in the english language
        numMessage, vulnerabilityinfo = returnDescription.returnDescription(portwords)  #checks the remaining words against the descriptions from the CVE

        stringresult = "Port usage: " + portinfo    #Creates message to user

        self.newwin = Toplevel(master=None)         #Pop up window with results
        self.newwin.geometry("900x300")

        self.listFrame=Frame(self.newwin)       #Frame for the results

        self.display = Label(self.newwin, text=stringresult, font=(16)) #messages to user
        self.display.pack(side=TOP)
        self.numResults = Label(self.newwin, text=numMessage, font=("BOLD",16))
        self.numResults.pack(side=TOP)
        self.internet = Label(self.newwin, text="For more information about any of these vulnerabilities, please double click on the vulnerability to be taken to its CVE entry and reference website")
        self.internet.pack(side=TOP)
        self.listFrame.pack(side=TOP, fill=BOTH)
        self.scrollH=Scrollbar(self.listFrame, orient="horizontal")     #creating and packing the scrollbars
        self.scrollH.pack(side=BOTTOM, fill=X)
        self.scrollV=Scrollbar(self.listFrame, orient="vertical")
        self.scrollV.pack(side=RIGHT, fill=Y)

        self.vulner = Listbox(self.listFrame, yscrollcommand=self.scrollV.set, xscrollcommand=self.scrollH.set)
        for item in vulnerabilityinfo:      #populates list
            self.vulner.insert(END, item)
        self.vulner.pack(fill="both", expand=1)

        self.scrollV.config(command=self.vulner.yview)  #associating the scrollbars to the list
        self.scrollH.config(command=self.vulner.xview)

        self.vulner.bind("<Double-Button-1>", self.launchInfo)      #binds double clicking on the list to the internet
        self.ok = Button(self.newwin, text='OK', command=lambda: self.newwin.destroy())
        self.ok.pack(side=TOP)

    # submit information and run
    def runportscan(self, ipaddr, startport, endport):

        #enable the text box to write into it
        #self.textbox.configure(state='enabled')
        self.counter = int(startport)
        self.end=int(endport)
        self.ratio=(100/(self.end-self.counter))
        self.numPorts=0
        self.barProgress=0
        self.statusVar.set("Scanning")  # updates the status in the GUI
        self.status.config(text="Scanning")
        self.statusText.insert(END, "Scanning ports from {0} to {1}".format(startport, endport))  # message to user#
        self.statusText.insert(END, "Using IP [0]".format(ipaddr))
        self.statusText.insert(END, "Starting")

        while self.counter < self.end:              #updates the counters
            result = portscan.runportscan(ipaddr,self.counter,self.counter+1)
            if result[0] != "":
                self.openPorts.insert(END, result[0])
            self.counter=self.counter+1
            self.numPorts=self.numPorts+result[1]
            self.barProgress=self.barProgress+self.ratio
            self.progressBar.config(value=self.barProgress)  # updates the progressBar
            self.progressUpdate.config(text=str(self.counter) +"/"+str(self.end))
            self.progressUpdate.update_idletasks()
            self.openPorts.update_idletasks()  # Refreshes GUI
            self.progressBar.update_idletasks()

        #run port scanner from portscan.py
    #    result = portscan.runportscan(ipaddr,startport,endport)
    #    self.textbox.insert(INSERT, result)
        self.statusText.insert(END, "Scan Complete")
        self.statusText.insert(END, "{0} Total ports open in range {1} to {2}".format(self.numPorts, startport, endport))  # final message to user
        self.statusVar.set("Ready")  # Updates status
        self.status.config(text="Ready")  # Refreshes Status
        self.openPorts.update_idletasks()  # Refreshes GUI
        tkinter.messagebox.showinfo('Status', 'Scan Complete!')  # message to user

    def clearData(self):  # Function for "New" option, clears all values and entry/textboxes

        self.statusText.delete(0,END)

        self.openPorts.delete(0, END)  # Clears the listbox

        self.progressBar.config(value=0)  # resets the progressBar
        self.progressBar.update_idletasks()

        self.entry1.delete(0,END)
        self.entry2.delete(0,END)
        self.entry3.delete(0,END)


    def signature(self):
        tkinter.messagebox.showinfo('About', " Created by Jonathon Trejo and Matt Sullivan \n For CSCI 5742 Cybersecurity Programming \n University of Colorado Denver \n Fall 2018")  # Awesomeness

    def launchInfo(self, event):    #function to launch websites associated with the vulnerabilities
        # Windows
        chrome_path = 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s'

#        Linux
#        chrome_path = '/usr/bin/google-chrome %s'

        workLine=self.vulner.get(ACTIVE).split("|")
        destination="http://cve.mitre.org/cgi-bin/cvename.cgi?name="+workLine[0]    #launches tab with CVE
        destination2=workLine[2]                                                    #launches tab from database
        webbrowser.get(chrome_path).open_new_tab(destination2)
        webbrowser.get(chrome_path).open_new_tab(destination)

def runwindow():
    root = Tk()
    my_gui = gui(root)
    root.mainloop()
