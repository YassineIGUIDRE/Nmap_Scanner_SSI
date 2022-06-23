#!/usr/bin/python3

import nmap
scanner = nmap.PortScanner()

#**********************Affichage du menu****************************#

print("Welcome, this is a simple nmap automation tool")
print("Nmap Version: ", scanner.nmap_version()) 
print("<----------------------------------------------------->")
response = input("""\nPlease enter the type of scan you want to run
                1)Host discovery Scan
                2)SYN ACK Scan
                3)UDP Scan
                4)OS Detection \n""")
print("You have selected option: ", response)

#-- Choix 1 - Scan pour la découverte des hôtes.

if response == '1':
    repo = input("""\nChoose a type of scan: 
               1)Scan the whole network
               2)Scan a specific target \n""")
    print("You have selected option: ", repo)
    ip_addr = input("Please enter the IP address you want to scan: ")
    if repo == '1': #Il s'agit d'une adresse réseau
        ip_addr = ip_addr + '/24'
        print("The IP you entered is: ", ip_addr)
        res = scanner.scan(hosts=ip_addr, arguments='-v -sn') #Exécuter le scan avec l'@IP et les arguments fournis
                                                              #Le résultat de ce scan est un dictionnaire
        if res['nmap']['scanstats']['uphosts'] == '0':  #S'il y'en a aucune machine dans le réseau
            print("No host found for this network")  
        else: #Si c'est le cas ou il y'a des machines dans le réseau
            for host in scanner.all_hosts(): #Parcourir les différentes hôtes trouvées
                if scanner[host].state() == 'up': #Afficher juste les machines qui sont UP
                    print('----------------------------------------------------')
                    print('Host : %s (%s)' % (host, scanner[host].hostname())) #Afficher l'@IP et le nom
                    print('State : %s' % scanner[host].state()) #Afficher son status
    elif repo == '2': #Il s'agit d'une machine spécifique
        print("The IP you entered is: ", ip_addr)
        scanner.scan(hosts=ip_addr, arguments='-v -sn') 
        if scanner[ip_addr].state() == 'up':
            print('Host : %s (%s) '% (ip_addr, scanner[ip_addr].hostname()))
            print('State : %s' % scanner[ip_addr].state())
        else:
            print("The host is unreachable")
    else:
        print("Please choose a number from the options above")   


#--Choix 2 - Le Scan TCP demi-ouvert ou SYN-ACK.
   
elif response == '2':

    ip_addr= input("Please enter the IP address of the host you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    scanner.scan(ip_addr, '1-1024', '-v -sS') # Scanner la machine avec les args fournis.
    print("Status: ", scanner[ip_addr].state()) # Afficher le status de la machine , s'elle est UP ou Down.
    if scanner[ip_addr].state() == 'up':
        print("IP address: ", scanner[ip_addr]['addresses']['ipv4'])
        print("Mac address: ", scanner[ip_addr]['addresses']['mac'])
        if 'tcp' in scanner[ip_addr].all_protocols(): # Si TCP existe dans le dict alors il y'en a des ports ouverts
            print("Protocol:", scanner[ip_addr].all_protocols()) # Aff le protocol
            print("Open Ports: ", scanner[ip_addr]['tcp'].keys()) # aff les ports ouverts
        else:
            print("All scanned ports are closed")  # Dans ce cas tous les ports sont fermées.
    else:
    	print("The host is unreachable")

#--Choix 3 - Le Scan UDP.

elif response == '3':

    ip_addr= input("Please enter the IP address of the host you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    scanner.scan(ip_addr, '1-1024', '-v -sU')  # Scanner la machine avec les args fournis.
    print("Status: ", scanner[ip_addr].state()) # Afficher le status de la machine , s'elle est UP ou Down.
    if scanner[ip_addr].state() == 'up':
        print("IP address: ", scanner[ip_addr]['addresses']['ipv4'])
        print("Mac address: ", scanner[ip_addr]['addresses']['mac'])
        if 'udp' in scanner[ip_addr].all_protocols(): #Si UDP existe dans le dict alors il y'en a des ports ouverts sous UDP
            print("protocol:", scanner[ip_addr].all_protocols())
            print("Open Ports: ", scanner[ip_addr]['udp'].keys())
        else:
            print("All scanned ports are closed")   # Dans le cas ou les ports sont fermées.
    else:
    	print("The host is unreachable")


#--Choix 4 - Détection du système d'exploitation:

elif response == '4':

    ip_addr= input("Please enter the IP address of the host you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    res = scanner.scan(ip_addr, arguments='-v -O') # Scanner la machine en obtenant la version du système d'exploitation.
    if res['scan'][ip_addr]['status']['state'] == 'up':
        print("OS name: ", res['scan'][ip_addr]['osmatch'][0]['name']) # Afficher la version du  SE.    
    else:
        print("The host is unreachable")

else:
    print("Please choose a number from the options above")
