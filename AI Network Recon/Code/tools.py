# Tools for the scripts
from subprocess import Popen, CalledProcessError, check_output, PIPE
import csv

# Identifies which protocol is used
def protoFinder(protoNumb):
    if (protoNumb == '1'):
        return 'ICMP'
    elif (protoNumb == '4'):
        return 'IPv4'
    elif (protoNumb == '6'):
        return 'TCP'
    elif (protoNumb == '17'):
        return 'UDP'
    elif (protoNumb == '41'):
        return 'IPv6'

# Checks for used interface, could fail if multiple interfaces is connected
def interfaceChecker():
    ifScan = Popen(['ls', '/sys/class/net/'], stdout = PIPE)
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
            pass

# Compares input to csv of OUI, if match it returns vendor name
def vendorScan(MACaddr):
    macSplit = MACaddr.split(':')
    oui = macSplit[0] + macSplit[1] + macSplit[2]
    with open('oui.csv') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            if oui.upper() == row[0]:
                return row[1]

# Gathers local info from client
def getLocalInfo(interface, debug):
    # Gets local IP for client
    h1 = Popen(['ifconfig', '-v', interface], stdout = PIPE)
    h2 = Popen(['sed', '-n', '-e', "s/^.*inet //p"], stdin = h1.stdout, stdout = PIPE)
    h3 = Popen(['grep', '-v', "127.0.0.1"], stdin = h2.stdout, stdout = PIPE)
    h4 = Popen(['sed', 's/[netmask].*$//'], stdin = h3.stdout, stdout = PIPE)
    lhost = h4.communicate()[0].decode('utf-8')

    # Gets netmask for network
    n1 = Popen(['ifconfig', '-v', interface], stdout = PIPE)
    n2 = Popen(['sed', '-n', '-e', 's/^.*netmask //p'], stdin = n1.stdout, stdout = PIPE)
    n3 = Popen(['grep', '-B0', 'broadcast'], stdin = n2.stdout, stdout = PIPE)
    n4 = Popen(['sed', 's/[broadcast].*$//'], stdin = n3.stdout, stdout = PIPE)
    netmask = n4.communicate()[0].decode('utf-8')

    # Print if debug
    if debug:
        print("lhost:\t\t\u001b[32;1m{}\u001b[0mnetmask:\t\u001b[36;1m{}\u001b[0m".format(lhost, netmask))

    return lhost, netmask

# Calculates the scannable IP range
# Example: lhost = 192.168.0.5 netmask = 255.255.0.0 range = 192.168.0.1 - 192.168.255.254
# 			excluding 192.168.0.5
def calculateRange(lhost, netmask, debug):
    octListHost = lhost.split('.')
    octListMask = netmask.split('.')
    scannable = 0


    for octet in range(len(octListMask)):
        if debug:
            print("octet scanned:\t{}".format(octet))

        if not '255' in octListMask[octet]:
            scannable += 1
            counter = 0

            for x in range(int(octListMask[octet]), 256):
                counter += 1
                octListMask[octet] = str(counter)

    if (scannable == 1):
        totalHost = (int(octListMask[3]) - 2)

    elif (scannable == 2):
        totalHost = (int(octListMask[2]) * int(octListMask[3]) - 2)

    else:
        totalHost = (int(octListMask[1]) * int(octListMask[2]) * int(octListMask[3]) - 2)

    # Print if debug
    if debug:
        print("Host:\t\u001b[32;1mOct1: {} Oct2: {} Oct3: {} Oct4: {}\u001b[0m\nMask:\t\u001b[36;1mOct1: {} Oct2: {} Oct3: {} Oct4: {}\u001b[0m".format(
        octListHost[0], octListHost[1], octListHost[2], octListHost[3], octListMask[0], octListMask[1], octListMask[2], octListMask[3]))
        print("Scannable Octets: {}".format(scannable))
        print("Scan range: {}.{}.{}.{}\tTotal possible hosts: {}".format(octListMask[0], octListMask[1], octListMask[2], octListMask[3], totalHost))

    return scannable, totalHost
