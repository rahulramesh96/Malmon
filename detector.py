#!/usr/bin/python3

from scapy.all import *
import sys
import os
import hashlib
import glob


print("Welcome to Maltect, the malware detector!")
print()

if "--net-mon" in sys.argv:
    if "--file-scan" in sys.argv:
        print("You cannot use both the features together.")
        exit()

def help():
    print("Switch \t\t\t Description")
    print()
    print("--file-scan \t\t shows the list of files in the directory")


def main():
    if ("--file-scan") in sys.argv:
        print("Welcome to malware scan!")
        print("The list of files under the current directory are: ")
        os.system("ls -alps")
        print()
        print("Now Calculating the hash of all the files and folders in the current directory...")
        path = str(subprocess.check_output(['pwd'], shell = False))
        new_path = path[2:-3]
        print(new_path)
        file = glob.glob(new_path + "/*.*")
        
        print()
        print('File name'+ '\t\t' + 'SHA-256 Hash')
        for f in file:
            with open(f, 'rb') as getsha256:
                data = getsha256.read()
                gethash = hashlib.sha256(data).hexdigest()
                file_name = os.path.basename(new_path)
                
                print( f + '\t\t' + gethash)
        print()
        print("All SHA-256 hashes performed.")
        print()
        hash_database = os.path.exists('malware_hash_database.txt')
        if hash_database is False:
            os.system('touch malware_hash_database.txt')

        fake_malware = os.path.exists('my_fake_malware.txt')
        if fake_malware is False:    
            os.system('touch my_fake_malware.txt')
        
        malware_hash = hashlib.sha256(open('my_fake_malware.txt','rb').read()).hexdigest()
        print("Malware's SHA-256 Hash is: " + malware_hash)
        print()

        text_file = open("./malware_hash_database.txt", "w")
        text_file.write(malware_hash + ':' + 'fake_malware')
        text_file.close()

        def mal_scan(file_name, string_to_search):
            """ Check if any line in the file contains given string """
            # Open the file in read only mode
            with open(file_name, 'r') as read_obj:
                # Read all lines in the file one by one
                for line in read_obj:
                    # For each line, check if line contains the string
                    if string_to_search in line:
                        print(line + '\033[1m found \033[1m' + 'in malware database')
                        
            return False
        
        mal_scan('malware_hash_database.txt', gethash)



if "--net-mon" in sys.argv:
    print("Welcome to NetMon")
    interface = sys.argv[sys.argv.index("--net-mon")+1]
    
    if interface not in conf.iface:
        print("Cannot proceed. Enter an active interface!")
        exit()
    ip = get_if_addr(interface)
    print("Your IP address of "+ interface + " is " + ip)

    pkt_count = 0
    pkt_to_sniff = pkt_count

    # This program will capture only the ARP packets.
    


    bad_ips = os.path.exists('bad_ips.txt')
    if bad_ips is False:
        os.system('touch bad_ips.txt ; sudo chmod 777 bad_ips.txt')



    proto_sniff = "arp"
    # The function will extract parameters from the packet and then log each packet
    def packet_log(packet):
        


    # Writing the packet information to the log file
        if(proto_sniff == "arp"):
        # Writing the data to the console output the file
            
            print(packet[0].psrc + "\t\t" + packet[0].pdst)
            bad_ips= open("bad_ips.txt", "r")
            bad_ips_content = bad_ips.read()
            if (packet[0].psrc) in bad_ips_content:
                print('\x1b[7;31;50m' + bad_ips_content + 'ALERT! Malicious IP found.' + '\x1b[0m')

    # Printing an informational message to the screen
    print("\n* Starting the capture...")
    print(" Source IP " + "\t\t" + " Destination IP ")

    # Running the sniffing process (with or without a filter)
            

    if proto_sniff == "arp":
        sniff(iface=conf.iface, filter=proto_sniff, count=int(pkt_to_sniff), prn=packet_log, timeout = 10)
        print("End of Capture.")
        print()

    else:
        print("\nCould not identify the protocol.\n")
        exit()  
    

        


if ("--help" or "-h") in sys.argv:
    help()


if __name__ == "__main__":
    main()
