from subprocess import Popen, CalledProcessError, check_output, PIPE
import argparse
from sqlTools import checkSQL
import tools
import re

from time import sleep
from time import time
from time import perf_counter

# Setup for CLI argument parsing
parser = argparse.ArgumentParser(prog='Dynamic_scanner.py', usage='%(prog)s \u001b[32;1m[-i enp0s3] \u001b[34;1m[-d True]\u001b[0m (Requires debugging ->) \u001b[36;1m[-l 10.0.0.188] [-n 255.255.255.0] [-t 254] [-f 1] [-s True] [-p True]\u001b[0m')
parser.add_argument("-i", "--interface", help='\u001b[32;1msets the interface (for automatic do not add -i)\u001b[0m')
parser.add_argument("-d", "--debugging", help='\u001b[34;1menables debugging mode, must be true to use other args\u001b[0m')
parser.add_argument("-l", "--lhost", help='\u001b[36;1mchanges lhost to specified value\u001b[0m')
parser.add_argument("-n", "--netmask", help='\u001b[36;1mchanges netmask to specified value\u001b[0m')
parser.add_argument("-t", "--totalhost", help='\u001b[36;1mchanges total hosts to specified value (does not use calculated hosts)\u001b[0m')
parser.add_argument("-f", "--found", help='\u001b[36;1mchanges detected netmask range\u001b[0m')
parser.add_argument("-s", "--scan", help='\u001b[36;1mprints all scanned IP addresses\u001b[0m')
parser.add_argument("-p", "--progress", help='\u001b[36;1mverbose info about scanned IP addresses\u001b[0m')
args = parser.parse_args()

# Defaults debugging to False and checks to see if it is enabled
debugging = False
try:
	if 'True' in args.debugging:
		debugging = args.debugging

# Checks if debugging arugments are chosen without enabling debugging
	elif 'False' in args.debugging and args.scan or args.progress or args.lhost or args.netmask or args.totalhost or args.found:
		print("Debugging is set to \u001b[33;1m{}\u001b[0m, \u001b[31;1mignoring\u001b[0m all debugging arguments...".format(args.debugging))
except:
	print("No arguments detected, running in default mode. -h or --help for more")
	pass

startMain = perf_counter()
def scan(lhost, totalHost, scannable, debug):
    hostSplit = lhost.split('.')
    oct2 = 0
    oct3 = 0
    oct4 = 0
    count = [0, 0, 0, 0, 0] # 0 - found, 1 - total skipped, 2 - host skipped, 3 - unreachable

    for ipRange in range(0, totalHost):
        # Goes through IP range dependent on the total hosts calculated
        #print(ipRange)
        if (scannable == 3):
            if (oct4 >= 253):
                oct4 = 0
                oct3 += 1
            elif (oct3 >= 253):
                oct4 = 0
                oct3 = 0
                oct2 += 1
            else:
                oct4 += 1

                # Creates IP
                IP = hostSplit[0] + '.' + str(oct2) + '.' + str(oct3) + '.' + str(oct4)

        elif (scannable == 2):
            if (oct4 >= 253):
                oct4 = 0
                oct3 += 1
            else:
                oct4 += 1

            # Creates IP
            IP = hostSplit[0] + '.' + hostSplit[1] + '.' + str(oct3) + '.' + str(oct4)

        elif (scannable == 1):
            oct4 += 1

            # Creates IP
            IP = hostSplit[0] + '.' + hostSplit[1] + '.' + hostSplit[2] + '.' + str(oct4)

        if debug:
            try:
                if 'True' in args.scan:
                    print("Scanning: {}".format(IP))
            except:
                pass

        IPsplit = IP.split('.')
        lhostSplit = lhost.split('.')

        if (int(IPsplit[0]) == int(lhostSplit[0]) and int(IPsplit[1]) == int(lhostSplit[1]) and int(IPsplit[2]) == int(lhostSplit[2]) and int(IPsplit[3]) == int(lhostSplit[3])):
            if args.progress is None:
                pass

            elif 'True' in args.progress:
                foundMacScan = Popen(['cat', '/sys/class/net/' + iface + '/address'], stdout = PIPE)
                foundMac = foundMacScan.communicate()[0].decode('utf-8')
                print("\u001b[31mSkipping Host:\tIP:\t{}\t\tReason: Client\t\t\tVendor: {}\u001b[0m\n".format(IP, tools.vendorScan(foundMac)))

            # ADDED FOR DEBUG, REMOVE WHEN DONE
            try:
                checkSQL(666, IP, foundMac, 'HOST', count[0], 1, '2019-08-17.16-00-00')
            except:
                pass
            count[2] += 1

        else:
            Popen(['ping', '-c', '1', IP], stdout = PIPE)
            pingResult = Popen(['arp', '-n', IP], stdout = PIPE).communicate()[0].decode('utf-8')

        try:
            if 'no entry' in pingResult or '(incomplete)' in pingResult:
                if debug:
                    try:
                        if 'True' in args.progress:
                            print("\u001b[31mSkipping Host:\tIP:\t{}\t\tReason: Unreachable\u001b[0m\n".format(IP))
                    except:
                        pass
                count[3] += 1

            else:
                foundMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", pingResult).groups()[0]
                vendor = tools.vendorScan(foundMac)
                if debug:
                    try:
                        if 'True' in args.progress:
                            print("Found host:\t\u001b[36mIP:\t{}\t\t\u001b[36;1mMAC: {}\t\t\033[32mVendor: {}\u001b[0m\n".format(IP, foundMac, vendor))
                    except:
                        pass
                count[0] += 1
                # For testing
                try:
                    checkSQL(count[0], IP, foundMac, vendor, count[0], 1, '2019-08-17.16-00-00')
                except:
                    pass

        # plt.hist(count[3]) # Graph test
        except Exception as e:
            print("ERROR when scanning: {}\t{}".format(IP, e)) # Uncomment for error message in scanning
            pass # Fight me

    count[1] = count[2] + count[3]
    print("Total Found: {} Total Skipped: {} Host Skipped: {} Host Unreachable: {}".format(count[0], count[1], count[2], count[3]))

# Runs interace checker then grabs local IP + netmask
if args.interface is None:
    iface = tools.interfaceChecker()
else:
    iface = args.interface

client, nmask = tools.getLocalInfo(iface, debugging)

# Checks if any default options are 
if debugging:
    print("DEBUGGING:\tON\nDEBUGGING:\tinterface: {}".format(iface))
if args.lhost:
    client = str(args.lhost)
    print("DEBUGGING:\tlhost: {}".format(client))
if args.netmask:
    nmask = str(args.netmask)
    print("DEBUGGING:\tnetmask: {}".format(nmask))
if args.totalhost:
    totHost = int(args.totalhost)
    print("DEBUGGING:\ttotal hosts: {}".format(totHost))
if args.found:
    scanFound = int(args.found)
    print("DEBUGGING:\tscannable: {}".format(scanFound))
#elsei:
    #scanFound, totHost = calculateRange(client, nmask, debugging)

scanFound, totHost = tools.calculateRange(client, nmask, debugging)
scan(client, totHost, scanFound, debugging)

# End timer
endMain = perf_counter()

# Calculates time elapsed and prints to CLI
print("Time elapsed: {:.1f}s".format((endMain - startMain)))
