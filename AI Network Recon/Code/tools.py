from subprocess import Popen, CalledProcessError, check_output, PIPE
import csv
import math


def interface_checker():
    ifScan = Popen(['ls', '/sys/class/net'], stdout = PIPE)
    ifList = ifScan.communicate()[0].decode('utf-8')
    ifListSplit = ifList.split('\n')
    ifListSplit.pop()

    routeScan = Popen(['netstat', '-rn'], stdout = PIPE)
    routeList = routeScan.communicate()[0].decode('utf-8')

    for intface in ifListSplit:
        try:
            if intface in routeList:
                if not 'tun' in intface and not 'lo' in intface:
                    return intface
        except:
            print('Interface not found')

def vendor_scan(MACaddr):
    macSplit = MACaddr.split(':')
    oui = macSplit[0] + macSplit[1] + macSplit[2]
    with open('oui.csv') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            if oui.upper() == row[0]:
                return row[1]

def get_local_info(interface): # I fucking miss ifconfig
    ''' Uses CLI commands to grab the local IP with subnet prefix (CIDR) and the MAC address of the NIC.
    The subnet prefix (CIDR) is a count of the 1 bits in the binary notation, this means we must convert it into
    dotted decimals to get the subnet mask.
    '''
    mac = Popen(['cat', f'/sys/class/net/{interface}/address'], stdout = PIPE).communicate()[0].decode('utf-8').rstrip()
    get_lhost = Popen(['ip', 'a', 'show', interface], stdout = PIPE)
    lhost = Popen(['awk', '/inet.*brd/ {print $2}'], stdin = get_lhost.stdout, \
                  stdout = PIPE).communicate()[0].decode('utf-8')
    lhost = lhost.split('/')
    cidr_prefix = lhost[1]
    lhost = str(lhost.pop(0))
    bin_netmask = '1' * int(cidr_prefix) + '0' * (32 -int(cidr_prefix))
    netmask_parts = []
    scannable_octets = 0

    for octet_bit in range(0, len(bin_netmask), 8):
        bin_octet = bin_netmask[octet_bit:][:8]
        octet = int(bin_octet, 2)

        if octet != 255:
            scannable_octets += 1
        netmask_parts.append(str(octet))
    return lhost, mac, '.'.join(netmask_parts), calculate_hosts(cidr_prefix), cidr_prefix, scannable_octets

def calculate_hosts(prefix):
    hosts = int(math.pow(2, (32 - int(prefix))) - 2)
    return hosts

def clamp_oct_IP(numb):
    if numb > 255:
        return 255
    else:
        return numb
