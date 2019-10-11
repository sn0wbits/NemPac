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