import socket
import sys
from scapy.all import ARP, Ether, srp

empty_exist = []

def scanner():            #this function is for scanning the network
    print("")
    ip = input(" Enter The Target IP For To Network: ")
    print("")
    print("      +----------------------------------------------------------+")
    print("      |  (IP Address)\t\t|\t  (MAC Address)\t\t |")
    print("      +----------------------------------------------------------+")
    arp_request = ARP(pdst=ip)
    ether_header = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = ether_header / arp_request
    responses = srp(arp_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for _, element in responses:
        client_dict = {"ip": element.psrc, "mac": element.hwsrc}
        client_list.append(client_dict)

    for item in client_list:
        if item["mac"] not in empty_exist:
            empty_exist.append(item["mac"])
            print(f"      |  {item['ip']:20}\t|\t{item['mac']:20}     |")
    print("      +----------------------------------------------------------+")
    return client_list

def discover_open_ports(ip_address):         #this function is for discovering open ports
    """Discover open ports on a given IP address."""
    print("")
    ip_addr = ip_address
    try:
        print(" [Notice] The Range Must Be Between 0 and 65535.\n")
        range1 = int(input(" Enter The First Range Number: "))
        range2 = int(input(" Enter The Second Range Number : "))
    except ValueError:
        print(" Invalid Input. Please Enter Integer Values.")
        return

    if not (0 <= range1 <= 65535 and 0 <= range2 <= 65535):
        print(" Range Must Be Between 0 and 65535.")
        return
    print("")
    print("      +----------------------------------------------------------+")
    for p in range(range1, range2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        connect = sock.connect_ex((ip_addr, p))
        if connect == 0:
            try:
                service = socket.getservbyport(p)
            except OSError:
                service = 'Unknown service'
            print(f"      | [+] Port {p:5} ---> is open  Service ---> {service:<15}|")
            sock.close()
    print("      +----------------------------------------------------------+")
    print("")

def main():             #this function is for the main function
    print("\n")
    print("""
     -**********.                                    .**********:
     +@@@@@@@@@@.                                    .@@@@@@@@@@=
     +@@@%======             .:-=++++=-:.             ======%@@@=        ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗       ██╗       ██████╗  ██████╗ ██████╗ ████████╗
     +@@@#              .-+#@@@@@@@@@@@@@@#+-.              #@@@=        ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝       ██║       ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
     +@@@#           .=#@@@@@@@%#*++*#%@@@@@@@#=.           #@@@=        ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝     ████████╗    ██████╔╝██║   ██║██████╔╝   ██║   
     -***=         -#@@@@@%+-.  .:--:.  .-+%@@@@@#-         =***:        ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗     ██╔═██╔═╝    ██╔═══╝ ██║   ██║██╔══██╗   ██║   
                .=%@@@@#=.    =%@@@@@@%=    .=#@@@@%=.                   ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗    ██████║      ██║     ╚██████╔╝██║  ██║   ██║   
               +@@@@@+.      *@@@@%#@@@@*      .+@@@@@+                  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝      ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
             :%@@@@+.       :@@@@.  .@@@@:       .+@@@@%:                                         ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
              +@@@@%=       .@@@@+::+@@@@.       =%@@@@+                                          ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
               .*@@@@@+:     -@@@@@@@@@@-     :+@@@@@*.                                           ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
                 .+@@@@@%+:   .=*%@@%*=.   :+%@@@@@+.                                             ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
     +@@@#          #@@@@@@@#+-:.    .:-+#@@@@@@@#          #@@@=                                 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
     +@@@#          #@@@%@@@@@@@@@@@@@@@@@@@@%@@@#          #@@@=                                 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
     +@@@#          #@@@+ .-*@@@@@@@@@@@@*-. +@@@#          #@@@=
     +@@@@%%%%%%.   #@@@+   -@@@@....@@@@-   +@@@#   .%%%%%%@@@@=
     +@@@@@@@@@@.   #@@@+   -@@@%    @@@@-   +@@@#   .@@@@@@@@@@=             +------------------------------------------------------------------------------------------------+
     .::::::::::    #@@@+   -@@@%    @@@@-   +@@@#    ::::::::::.             | Full Name       :: Mohamed Khaled Nassar                                                       |
                    #@@@+   -@@@%    @@@@-   +@@@#                            | Course Name     :: Networks Security                                                           |         
                  =@@@@@-   -@@@%    @@@@-   -@@@@@=                          | Course Code     :: CSE 231                                                                     |
        .-+++=: -%@@@@+     -@@@%    @@@@-     +@@@@%- :=+++-.                | Dr. Name        :: Aida Nasr                                                                   |
      :#@@@@@@@@@@@@*.      =@@@%    %@@@=      .*@@@@@@@@@@@@#:              | Academic Mail   :: 1800364@el-eng.menofia.edu.eg                                               |
     .@@@@#+*@@@@@#:       .@@@@=    =@@@@.       :#@@@@@*+%@@@@.             |------------------------------------------------------------------------------------------------|
     +@@@%   .@@@@:     :-=#@@@#      #@@@#=-:     :@@@@.   %@@@-             | The Description :: This script is a network and port scanner tool that allows users to discover| 
     :@@@@*-=#@@@%   .*@@@@@@@@-      -@@@@@@@@*.   %@@@#=-*@@@@.             |                    devices on the network and discover which ports are open on those devices or|
      -%@@@@@@@@#.  :@@@@%#%@@@@=    =@@@@%#%@@@@:  .#@@@@@@@@%-              |                    any IP address for domain name.                                             |
        -+###*=:    *@@@*   =@@@%    %@@@=   *@@@*    :=*###+-                +------------------------------------------------------------------------------------------------+
                    +@@@%-:-#@@@#    #@@@#-:-%@@@+
                     *@@@@@@@@@#.    .#@@@@@@@@@*
                      .=*#%#*+:        :+*#%#*=.    """)
    print("\n\n\n")
    while True:
        print("\n     [1] Discover Devices On The Network")
        print("     [2] Discover Open Ports On a Device Or Domain")
        print("     [3] Exit")
        choice = input("\n Choose An Option: ")
        if choice == '1':
            client_list = scanner()
            discover_option = input("\n Do You Want To Discover Open Ports On Any Of The Devices? (yes/no): ")
            if discover_option.lower() in ['yes', 'y']:
                ip_address = input("\n Enter The IP Address Of The Device To Discover Open Ports On It: ")
                discover_open_ports(ip_address)
            elif discover_option.lower() in ['no', 'n']:
                domain_option = input("\n Do you want to discover open ports on any of the Domain name? (yes/no): ")
                if domain_option.lower() in ['yes', 'y']:
                    ip_address = socket.gethostbyname(input("\n Enter the IP address of the Domain name to discover open ports on it: "))
                    discover_open_ports(ip_address)
                elif domain_option.lower() in ['no', 'n']:
                    exit_option = input("\n Do you Do you want to exit the program? (yes/no): ")
                    if exit_option.lower() in ['yes', 'y']:
                        sys.exit()
                    else:
                        continue
                else:
                    print("\n Invalid choice. Please try again.")
            else:
                print("\n Invalid choice. Please try again.")
        elif choice == '2':
            ip_address = input("\n Enter IP address to discover open ports: ")
            discover_open_ports(ip_address)
        elif choice == '3':
            sys.exit()
        else:
            print("\n Invalid choice. Please try again.")

        while True:
            repeat = input("\n Do You Want To Execute The Program Again? (yes/no): ")
            if repeat.lower() in ('yes', 'y'):
                break           # Go back to the main menu
            elif repeat.lower() in ('no', 'n'):
                sys.exit()
            else:
                print("\n Invalid Choice. Please Try Gain.")

if __name__ == "__main__":
    main()
