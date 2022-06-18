#!/usr/bin/python3


from scapy.all import *
import sys
import os

print("Welcome to Netmon!")

def help():
    print("--file-scan /t/t/t shows the list of files in the directory")


def main():
    if "--file-scan" in sys.argv:
        os.system("ls")


if "--help" or ""



if __name__ == "__main__":
    main()
