from subprocess import Popen, CalledProcessError, check_output, PIPE
import argparse
import socket
# #import sqlTools import checlSQL -- Implement later
import tools
import math
import re

parser = argparse.ArgumentParser(prog='Dynamic_scanner.py', usage='%(prog)s) [-i wlan0]')
parser.add_argument('-i', '--interface', help='sets the interface (for automatic detection do not add this)')
args = parser.parse_args()


if (args.interface is None):
    iface = tools.interface_checker()
else:
    iface = args.interface

class Scanner:
    def __init__(self):
        self.lhost = None
        self.ip_list = []
        self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_tcp.settimeout(.5)
        self.port_list_tcp = [20, 21, 22, 23, 25, 80, 443] # FTP, SSH, Telnet, SMTP, HTTP, HTTPS
        self.port_list_udp = [60, 520, 1812, 5004, 5060]   # TFTP, RIP, RADIUS, RTP, SIP
        self.ip_mac_list = []

    def gen_IP(self, lhost, prefix, scannable):
        ''' calculate all usable IP addresses using the CIDR notation,
        this is done by using the formulas 2^(32-CIDR) - 2,
        (256 - 2^(32-CIDR)) / 256 and ((256 - 2^(32-CIDR)) / 256) / 256
        '''
        self.hostSplit = lhost.split('.')
        oct3 = tools.clamp_oct_IP(int(math.pow(2, (32 - int(prefix))) - 2))
        oct2 = tools.clamp_oct_IP(int(abs(256 - math.pow(2, (32 - int(prefix))) / 256)))
        oct1 = tools.clamp_oct_IP(int(abs((256 - math.pow(2, (32 - int(prefix))) / 256) / 256)))

        if scannable == 1:
            for cur_octet in range(1, (oct3 + 1)):
                self.ip_list.append(self.hostSplit[0] + '.' + self.hostSplit[1] + '.' + \
                                    self.hostSplit[2] + '.' + str(cur_octet))
        elif scannable == 2:
            for cur_octet2 in range(1, (oct2 + 1)):
                for cur_octet3 in range(1, oct3):
                    self.ip_list.append(self.hostSplit[0] + '.' + self.hostSplit[1] + '.' + \
                                        str(cur_octet2) + '.' + str(cur_octet3))
        elif scannable == 3:
            for cur_octet1 in range(1, (oct1 + 1)):
                for cur_octet2 in range(1, oct2):
                    for cur_octet3 in range(1, oct3):
                        self.ip_list.append(self.hostSplit[0] + '.' + str(cur_octet1) + '.' + \
                                            str(cur_octet2) + '.' + str(cur_octet3))
        else:
            raise ValueError(f'Value {scannable} is not a valid value!')
        return self.ip_list

    def remove_lhost(self, lhost):
        self.ip_list.pop(self.ip_list.index(lhost))

    def ping_scan(self, ip):
        Popen(['ping', '-c', '1', ip], stdout = PIPE)
        ping_result = Popen(['ip', 'neigh'], stdout = PIPE)
        ping_result = Popen(['grep', ip], stdin=ping_result.stdout, stdout = PIPE).communicate()[0].decode('utf-8')
        if 'DELAY' in ping_result or 'STABLE' in ping_result:
            #print(f'\033[92m{ping_result}\033[0m')
            self.ip_mac_list.append(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                              + '|(?:[0-9a-fA-F]:?){12}', ping_result))
        else:
            #print(f'\033[93mIP - {ip}\tnot found\033[0m')
            pass

    def tcp_scan(self, ip):
        for port in self.port_list_tcp:
            try:
                self.socket_tcp.connect((ip, port))
                print(f'IP - {ip}\tPORT - {port}\tfound')
            except:
                #print(f'IP - {ip}\tPORT - {port}\tnot found')
                pass
            self.socket_tcp.close()

    def udp_scan(self, ip):
        test = input('0')
        for port in self.port_list_udp:
            self.socket_udp.sendto(test, (ip, port))
            while True:
                data, addr = sock.recvfrom(1024)
                print(f'Data be - {data}')

local_host, mac_address, n_netmask, n_total_hosts, n_prefix, scannable = tools.get_local_info(iface)
scan = Scanner()
scan.gen_IP(local_host, n_prefix, scannable)
scan.remove_lhost(local_host)

for ip in scan.ip_list:
    scan.ping_scan(ip)
    scan.tcp_scan(ip)
    #print(scan.ping_scan(ip))
    #print(scan.tcp_scan(ip))
    #print(scan.udp_scan(ip))

for x in range(1, len(scan.ip_mac_list)):
    print(f'IP - {scan.ip_mac_list[x][0]}\nMAC - {scan.ip_mac_list[x][1]}'
          + f'\nOUI - {tools.vendor_scan(scan.ip_mac_list[x][1])}\n')
