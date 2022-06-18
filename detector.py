#!/usr/bin/python3


from scapy.all import *
import sys
import os

print("Welcome to Netmon, the malware detector!")
print()

def help():
    print("\bSwitch \t\t \bDescription")
    print()
    print("--file-scan \t\t shows the list of files in the directory")


def main():
    if "--file-scan" in sys.argv:
        os.system("ls -alps")


if "--help" or "-h" in sys.argv:
    help()


if __name__ == "__main__":
    main()
