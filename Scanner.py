import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print(".................................................")

ip_add = input("Please enter ip address you want to scan: ")
print("The ip you entered is: ", ip_add)
type(ip_add)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive scan\n""")
print("You have selected option: ", resp)

if resp == '1':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("The open ports: ", scanner[ip_add]['tcp'].keys())
elif resp == '2':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("The open ports: ", scanner[ip_add]['udp'].keys())
elif resp == '3':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("The open ports: ", scanner[ip_add]['tcp'].keys())
elif resp >= '4':
    print("Invalid input")
