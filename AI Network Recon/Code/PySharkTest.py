#############################################
# Using PyShark we can capture packets from #
# an interface, adding filters is also      #
# possible.                                 #
#############################################
import pyshark as ps
import argparse
from sqlTools import sqlPorty
import tools
import csv

parser = argparse.ArgumentParser(description='Capture network packets')
parser.add_argument("-i", "--interface", help='interface to use')
parser.add_argument("-p", "--packets", help='limit scan for number of packets')
parser.add_argument("-t", "--timeout", help='limit scan to timeout')
parser.add_argument("-a", "--all", help='shows all info from packets')
parser.add_argument("-d", "--debug", help='shows debug messages')
args = parser.parse_args()

args.timeout = 1
#args.debug = 'True'

# Scans for packets
def scanner(interface):
    if (interface and (args.packets or args.timeout)):
        # For numbering packets
        pckNumb = 0

        if (interface and (args.packets or args.timeout)):
            capture = ps.LiveCapture(interface=interface)

            if (args.packets is None):
                pass

            elif (int(args.packets) >= 1):
                print("Packet count set to {}".format(int(args.packets)))
                capture.sniff(packet_count=int(args.packets))

            if (args.timeout is None):
                pass

            elif (int(args.timeout) >= 1):
                print("Timout set to {}".format(int(args.timeout)))

            #### DEBUGGING ####

            for packet in capture:
                if (args.debug is None):
                    pass

                elif ('True' in args.debug):
                    try:
                        if (packet.ip.src is None) and (packet.ip.dst is None):
                            # If there is no src and dst IPin the packet, it will be ignored.
                            # This is becuase it is not possible to track it.
                            pass

                        elif (packet.ip.src is None) and (packet.ip.dst is not None):
                            packet.ip.src = "N/A"

                        elif (packet.ip.dst is None) and (packet.ip.src is not None):
                            packet.ip.dst = "N/A"

                        else:
                            srcVend = tools.vendorScan(packet.eth.src)
                            destVend = tools.vendorScan(packet.eth.dst)
                            print("Packet: {}\tLength: {}\b".format(pckNumb, packet.length))
                                # Makes a line for ease of understanding
                            print("\t{}".format(76*"-"))
                            print("\tSource IP:...........{}\t\tDestination IP:...{}".format(packet.ip.src, packet.ip.dst))
                            print("\tSource MAC:..........{}\tDestination MAC:..{}".format(packet.eth.src, packet.eth.dst))
                            print("\tSource Vendor:.......{}\n\tDestination Vendor:..{}".format(srcVend, destVend))
                            print("\tProtocol:............{} - {}".format(packet.ip.proto, tools.protoFinder(packet.ip.proto)))

                            if ('6' in packet.ip.proto):
                                print("\tTCP Source:..........{}\t\tTCP Dest:..{}".format(packet.tcp.srcport, packet.tcp.dstport))

                            elif ('17' in packet.ip.proto):
                                print("\tUDP Source:..........{}\t\tUDP Dest:..{}".format(packet.udp.srcport, packet.udp.dstport))

                            try:
                                print("\tRaw Data:.{}".format(packet.data.data))
                            except:
                                print("\tRaw Data:.{}".format('N/A'))

                            print('\n\n')

                            pckNumb += 1

                    except AttributeError as e:
                        print(e)
                        pass

                if (args.all is None):
                    pass

                elif ('True' in args.all):
                    print(packet)
                
                # For testing SQL stuff
                try:
                    if ('6' in packet.ip.proto):
                        sqlPorty(packet.tcp.dstport, packet.eth.src)

                    elif ('17' in packet.ip.proto):
                        sqlPorty(packet.udp.dstport, packet.eth.src)
                except:
                    pass
            #### DEBUGGING END ####

# Execute scanner
if args.interface is None:
    iface = tools.interfaceChecker()
else:
    iface = args.interface

scanner(iface)
