#! /usr/bin/env python2

from Tkinter import *
from ttk import *
from tkMessageBox import showwarning
from os import geteuid
from sys import exit
from gui import MITMerFrame


class MITMer(Tk):

    def __init__(self):
        Tk.__init__(self)
        self.withdraw()
        self.title("MITMer")
        if geteuid() != 0:
            showwarning("Error", "Please run as root/superuser")
            exit()
        self.deiconify()
        MITMerFrame(self)
        self.mainloop()


if __name__ == '__main__':
    MITMer()
