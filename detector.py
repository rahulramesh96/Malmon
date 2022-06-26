#!/usr/bin/python3

from scapy.all import * # This library is used for dealing with packets.
import sys # The sys module in the language offers a number of functions and variables to control python interpreter.
import os # OS library is used to run commands to interact with teh Operating System.
import hashlib # A library to deal with hashes.
import glob # Glob module locates all pathnames that match a given pattern.
import threading # A library to performing threading to speed up the process.
import time # A time module to keep track of time



if '--net-mon' in sys.argv: # If the input in the CLI has --net-mon switch then the loop will be entered.
    if "--file-scan" in sys.argv: # If the --file-scan switch is present after --net-mon or interchangeably, it will further enter the loop.
        print("Welcome to Malmon!") # Prints the welcome message.
        print('You cannot use both the features together.') # Both the switches --net-mon and --file-scan cannot be used simultaneuosly.
        exit() #

if '--file-scan' in sys.argv: # If the input in the CLI has --file-scan switch then the loop will be entered.
    if "--net-mon" in sys.argv: # If the --file-scan switch is present after --net-mon or interchangeably, it will further enter the loop.
        print("Welcome to Malmon!") # Prints the welcome message.
        print('You cannot use both the features together.') # Both the switches --net-mon and --file-scan cannot be used simultaneuosly.
        exit() #

if len(sys.argv)==1: # If there is no switch supplied while running the tool, Malmon would assist you to run a help command to use the tool better.
    print('Welcome to Malmon! The antimalware scanner and network monitoring tool.') # Prints the welcome message.
    print('Please use -h to view help')

def help(): # This is the help function, which will be triggered if the user inputs a '-h' or '--help' as switches.
    print('Welcome to Malmon! The antimalware scanner and network monitoring tool.')
    print()
    print("Switch \t\t\t\t\t Description")
    print()
    print("--file-scan \t\t\t\t Checks the current working directory for malware")
    print("--net-mon <interface name> \t\t Network monitoring tool")


def main(): # This is the main function where the entire code for the program resides.
    if ("--file-scan") in sys.argv: # This switch scans for malware in the current director with the existing malware hash databse and send out an alert if any malicious file is found.
        print("Welcome to malware scan mode!")
        print("The list of files under the current directory are: ")
        os.system("ls -alps") # We will list out all the files present in the present working directory.
        print()
        print("Now Calculating the hash of all the files and folders in the current directory...")
        path = str(subprocess.check_output(['pwd'], shell = False)) # Setting a variable called 'path' which can store the present working directory of the application.
        new_path = path[2:-3] # The new_path variable has the path variable sanitised.
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
            start = time.time()
            # Open the file in read only mode
            with open(file_name, 'r') as read_obj:
                # Read all lines in the file one by one
                for line in read_obj:
                    
                    # For each line, check if line contains the string
                    if string_to_search in line:
                        print(line + '\033[1m' + ' found ' + '\033[1m' + 'in malware database')
                        end =time.time()
                        final_time = end - start
                        print('scan completed in', final_time , 'seconds')
                        print()
            return False
        
        mal_scan('malware_hash_database.txt', malware_hash)

        # Below is the process of performing the malware scan using threading
        print('Malware Scan with THREADING')
        start2 = time.time() 
        x = threading.Thread(target = mal_scan, args = ('malware_hash_database.txt', gethash))
        x.start()
        
        print('Active threads: ' , threading.active_count())
        end2 = time.time()
        final_time_2 = end2 - start2
        print('scan completed in ', final_time_2 , 'seconds')



    if "--net-mon" in sys.argv:
        print("Welcome to Network Monitoring tool!")
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
            os.system('echo "10.0.2.5" >> bad_ips.txt')  #sample IP Address 1
            os.system('echo "10.0.2.30" >> bad_ips.txt') #sample IP Address 2
            os.system('echo "10.0.2.100" >> bad_ips.txt') #sample IP Address 3
        bad_domains = os.path.exists('bad_domains.txt')
        if bad_domains is False:
            os.system('touch bad_domains.txt ; sudo chmod 777 bad_domains.txt')
            os.system('echo "www.google.com" > bad_domains.txt')
        

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
                    print('\x1b[7;31;50m' + packet[0].psrc + '\t\t' + 'ALERT! Malicious IP found.' + '\x1b[0m')

        # Printing an informational message to the screen
        print("\n* Starting the capture...")
        print(" Source IP " + "\t\t" + " Destination IP ")

        # Running the sniffing process (with or without a filter)
                

        if proto_sniff == "arp":
            sniff(iface=interface, filter=proto_sniff, count=int(pkt_to_sniff), prn=packet_log, timeout = 1)
            print("End of Capture.")
            print()
            

        else:
            print("\nCould not identify the protocol.\n")
            exit()  


        packet = IP(dst="1.1.1.1") / UDP() / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        
        domain_name = str(packet.qd.qname)
        domain = str(domain_name[1:])
        print('Visited Domain ' + domain)
        
        bad_domains= open("bad_domains.txt", "r")
        bad_domains_content = bad_domains.read()  
        if domain in bad_domains_content:

            print('Reading through dangerous domains...')
            print(bad_domains_content)
            print()
            print('Domain' + '\t\t\t\t' + 'Description')
            print()
            print('\x1b[7;31;50m' + domain + '\t\t' + 'ALERT! Malicious Domain found.' + '\x1b[0m')
      
if ("--help") in sys.argv:
    if len(sys.argv)==2:
        help()
    else:
        print("Do not use more than one switch for help.")
        exit()

if ("-h") in sys.argv:
    if len(sys.argv)==2:
        help()
    else:
        print('Do not use more than one switch for help.')
        exit()

if __name__ == "__main__":
    main()
