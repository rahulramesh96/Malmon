#!/usr/bin/python3

from scapy.all import *
import sys
import os
import hashlib


print("Welcome to Netmon, the malware detector!")
print()

def help():
    print("Switch \t\t\t Description")
    print()
    print("--file-scan \t\t shows the list of files in the directory")


def main():
    if ("--file-scan") in sys.argv:
        print("The list of files under the current directory are: ")
        os.system("ls -alps")
        print()
        print("Now Calculating the hash of all the files and folders in the current directory...")
        path = str(subprocess.check_output(['pwd'], shell = False))
        new_path = path[2:-3]
        print(new_path)
        print("The present working directory is: ", new_path)
        os.system("cd "+ new_path)


if ("--help" or "-h") in sys.argv:
    help()


if __name__ == "__main__":
    main()
