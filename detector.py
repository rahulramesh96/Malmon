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
    print('Welcome to Malmon! The antimalware scanner and network monitoring tool. Maintained by Rahul Ramesh. Student ID = R00207989.')
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
        file = glob.glob(new_path + "/*.*") # The 'file' variable holds the name of the files along with the path in the present working directory.
        
        print()
        print('File name'+ '\t\t\t\t\t\t' + 'SHA-256 Hash') # Printing the file name with the SHA-256 hash of the same file.
        
        for f in file: # f will be iterated through the 'file' variable line by line
            with open(f, 'rb') as getsha256: # We open the file in read mode using 'rb' 
                data = getsha256.read() # the read function reads the first file and stores it in a temporary variable called data.
                gethash = hashlib.sha256(data).hexdigest() # We can now feed in the data in the sha-256 hashing algorithm and save it in the variable gethash
                print( f + '\t\t\t' + gethash) # The filename and its associated hash is printed in two columns

        print()
        print("All SHA-256 hashes performed.")
        print()
        hash_database = os.path.exists('malware_hash_database.txt') # Checks if there is a malware database.
        if hash_database is False: # If there is no Hash Database, the next line will create a hash database.
            os.system('touch malware_hash_database.txt')

        fake_malware = os.path.exists('my_fake_malware.txt') # Checks if the malware is present in the system.
        if fake_malware is False:    # If the malware is not present, the next would create a new malware.
            os.system('touch my_fake_malware.txt')
        
        malware_hash = hashlib.sha256(open('my_fake_malware.txt','rb').read()).hexdigest() # malware_hash holds the SHA-256 hash of the 'my_fake_malware'
        print("Malware's SHA-256 Hash is: " + malware_hash) # The Malware's SHA-256 hash is printed.
        print()

        text_file = open("./malware_hash_database.txt", "w") # The malware database is opened in write mode.
        text_file.write(malware_hash + ':' + 'fake_malware') # The hash of the malware is written in the database.
        text_file.close() # The file is closed.

        def mal_scan(file_name, string): # Checks if any string matches in the context of the file.
            
            start = time.time() # We start the timer to compute the elapsed execution time, 'start' variable holds the elapsed time in runtime.
            
            with open(file_name, 'r') as read_obj: # Open the file in read only mode
                
                for line in read_obj: # Read all lines in the file one by one
                    
                    
                    if string in line: # check if the string is present in each line
                        print(line + '\033[1m' + ' found ' + '\033[1m' + 'in malware database') # If the string is found, then the malware is present in the database
                        end = time.time() # 'end' variable holds the value of elapsed time in runtime.
                        final_time = end - start # final_time gives the value of the total time in seconds by subtracting the end time and the start time.
                        print('scan completed in', final_time , 'seconds') # The elapsed time is shown after the above function is executed.
                        print()
            return False
        
        mal_scan('malware_hash_database.txt', malware_hash) # mal_scan() function is called with arguments passed as 'malware_hash_databse.txt' and the 'malware_hash' to search through the  malware databse

        # Below is the process of performing the malware scan using threading
        print('Malware Scan with THREADING')
        start2 = time.time() # We start the timer to compute the elapsed execution time, 'start2' variable holds the elapsed time in runtime.
        x = threading.Thread(target = mal_scan, args = ('malware_hash_database.txt', gethash)) # Making use of threading here to speed up the process. the target function is mal_scan to call. The arguments are passed in as well.
        x.start() # x is the variable that holds the thread. The thread x is started.
        
        print('Active threads: ' , threading.active_count()) # This prints out the number of active threads.
        end2 = time.time() # 'end2' variable holds the value of elapsed time in runtime.
        final_time_2 = end2 - start2 # 'final_time_2' gives the value of the total time in seconds by subtracting the end time and the start time.
        print('scan completed in ', final_time_2 , 'seconds') # The total execution time using threading is shown.

    if "--net-mon" in sys.argv: # When the input contains the '--net-mon' switch.
        print("Welcome to Network Monitoring tool!") # Prints the welcome message.
        interface = sys.argv[sys.argv.index("--net-mon")+1] # The interface is taken as the immediate next CLI argument after the '--net-mon' switch
        
        if interface not in conf.iface: # If the interface specified in the argument is not valid.
            print("Cannot proceed. Enter an active interface!") # The program will exit and would not proceed.
            exit() # The program exits post the error.
        ip = get_if_addr(interface) # We get the ip address of the interface and store it in the variable 'ip'
        print("Your IP address of "+ interface + " is " + ip) # The IP address of the resepective interface is printed.

        pkt_to_sniff = 0 # The pkt_sniff is set to 0

        # Below code will capture the ARP packets on the specified interface.
        
        bad_ips = os.path.exists('bad_ips.txt') # Checks if the file bad_ips.txt is present in the given location.
        if bad_ips is False: # If the file is not present, the file will be created and be inserted with few sample bad IP Addresses.
            os.system('touch bad_ips.txt ; sudo chmod 755 bad_ips.txt') # We create the bad_ips.txt file and give a file permission of u=rwx, g=rx, o=rx
            os.system('echo "10.0.2.5" >> bad_ips.txt')  #sample bad IP Address 1
            os.system('echo "10.0.2.30" >> bad_ips.txt') #sample bad IP Address 2
            os.system('echo "10.0.2.100" >> bad_ips.txt') #sample bad IP Address 3
        bad_domains = os.path.exists('bad_domains.txt') # Check is the bad_domains.txt file is present in the given location.
        if bad_domains is False: # If the file is not present, the file will be created and be inserted with few sample IP Addresses.
            os.system('touch bad_domains.txt ; sudo chmod 755 bad_domains.txt') # We create the file called bad_domains.txt and give a file permission of u=rwx, g=rx, o=rx
            os.system('echo "www.google.com" > bad_domains.txt') # sample malicious domain 1 is google.com

        
        proto_sniff = "arp" # We will set the proto_sniff variable to arp protocol
        # The function will extract parameters from the packet and then log each packet
        def packet_log(packet): # The function packet_log takes in 'packet' as a parameter

        # Writing the packet information to the log file
            if(proto_sniff == "arp"): # As we are sniffing only in the arp protocol.
            # Writing the data to console output the file
                
                print(packet[0].psrc + "\t\t" + packet[0].pdst) # The source IP Address and the destination IP Address of the packet is shown
                bad_ips= open("bad_ips.txt", "r") # The bad_ips.txt file is read.
                bad_ips_content = bad_ips.read() # The bad_ips is read and stored in the variable bad_ips_content.
                if (packet[0].psrc) in bad_ips_content: # We check with an if statement if the source ip address ofthe packet is present in the bad_ips list.
                    print('\x1b[7;31;50m' + packet[0].psrc + '\t\t' + 'ALERT! Malicious IP found.' + '\x1b[0m') # This will print the IP address of the malicious machine in the network.

        # Printing an informational message to the screen
        print("\n* Starting the capture...") 
        print(" Source IP " + "\t\t" + " Destination IP ")

        # Running the sniffing process (with or without a filter)
                

        if proto_sniff == "arp": # We will sniff only the packets that have ARP protocol.
            sniff(iface=interface, filter=proto_sniff, count=int(pkt_to_sniff), prn=packet_log, timeout = 2) # This is the sniff function from scapy which will functions as a passive scan for 20 seconds.
            print("End of Capture.")
            print()

        else:
            print("\nCould not identify the protocol.\n") # If no ARP packets were sniffed, this will return with an error.
            exit()  


        packet = IP(dst="1.1.1.1") / UDP() / DNS(rd=1, qd=DNSQR(qname="www.google.com")) # We can try sending a DNS Query with the domain name www.google.com.
 
        
        domain_name = str(packet.qd.qname) # This will convert the qname 'www.google.com' to string and store it in the domain_name variable.
        domain = str(domain_name[1:]) # This will strip off the character 'b' in the domain_name variable
        new_domain = domain[1:-1] # This will strip off the apostrophe in the beginning of the domain and the ending of the domain.
        print('Queried Domain ' + new_domain) # The queried domain will be printed here.
        
        bad_domains= open("bad_domains.txt", "r") # The bad domains text file will be opened in read mode.
        bad_domains_content = bad_domains.read()  # The bad_domains_content will store each line bad_domains.txt
        if new_domain in bad_domains_content: # The bad_domains_content will be checked with the queried domain name in the below loop.

            print('Reading through dangerous domains...')
            print(bad_domains_content) # This will print out the list of malicious domains.
            print()
            print('Domain' + '\t\t\t\t' + 'Description')
            print()
            try:
                print('\x1b[7;31;50m' + new_domain + '\t\t' + 'ALERT! Malicious Domain found.' + '\x1b[0m')
            except:
                print('No malicious domains visited.')
      
if ("--help") in sys.argv: # If '--help' switch is present in the CLI argument, the length of the CLI arguments are collected
    if len(sys.argv)==2: # The length of the arguments are checked to see if there is no collision.
        help() # The help function is called.
    else:
        print("Do not use more than one switch for help.") # Prints out to display only -h or --help can be used as a switch for help.
        exit()

if ("-h") in sys.argv: # If '-h' switch is present in the CLI argument, the length of the CLI arguments are collected
    if len(sys.argv)==2: # The length of the arguments are checked to see if there is no collision.
        help() # The help function is called.
    else:
        print('Do not use more than one switch for help.') # Prints out to display only -h or --help can be used as a switch for help.
        exit()

if __name__ == "__main__": # Checks if any of the function's name is main, if yes, then enter this loop.
    main() # This is the main function which will be executed first when the program is executed.
