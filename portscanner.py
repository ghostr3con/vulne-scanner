import socket
from IPy import IP


class PortScan:
    banners = []
    open_ports = []

    def __init__(self, target, port_num):
        self.target = target
        self.port_num = port_num

    def scan(self):
        """
        Function that  implements the  scanner
        :param target:
        :return:
        """
        # check the IP

        # print  target that is being scanned
        print('\n' + 'Scanning Target ' + str(self.target))
        # loop through each of the ports specified scanning them in the  process
        for port in range(21, 25):
            self.scan_ports(port)


    def check_ip(self):
        """
        Function that checks if the supplied input is an IP address or domain name
        :param host:
        :return:
        """
        try:
            IP(self.target)
            return self.target
        except ValueError:
            return socket.gethostbyaddr(self.target)

    def scan_ports(self,iport):
        """
        Function that connects to the host using the  IP and port number to verify  open ports
        retrieves the banner as well
        :param target:
        :param iport:
        :return:
        """
        try:
            # socket try  catch
            converted_ip = self.check_ip()
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((converted_ip, iport))
            self.open_ports.append(iport)
            try:
                #banner try catch
                banner = sock.recv(1024).decode().strip('\n').strip('\r')
                self.banners.append(banner)
                #print('[+]Open port ' + str(iport) + ' : ' + str(banner))
            except:
                print('[+] Open port :' + str(iport))
                self.banners.append('Empty')
            sock.close()

        except:
            pass
            #print('[-]Port ' + str(iport) + ' is closed')





