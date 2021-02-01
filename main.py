import portscanner

target_ip = input('[+] * Enter target to scan for vuln open ports: ')

port_num = int(input('[+] * Enter no of ports to scan (500 - first 500 ports: '))

#vuln_repo = input('[+] * Enter path to file with vulnerable softwares:  ')

vuln_repo = 'vulnbanners.txt'

print('\n')


# initialize an object of the PortScanner class

target = portscanner.PortScan(target_ip, port_num)

target.scan()

# Perform Vuln scan via  match with banners found in the vuln database


with open(vuln_repo, 'r') as file:
    count = 0
    while count < len(target.banners):
        for banner in target.banners:
            #navigate to the beginning of the file every run
            file.seek(0)
            for line in file.readlines():

                if line.strip('\n').strip('\r') in banner:
                    print('[!!] VULNERABLE : ' + banner + ' ON PORT: ' + str(target.open_ports[count]))
            count += 1
