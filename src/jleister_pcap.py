'''
Created on Aug 28, 2017

@author: jleister
'''

import argparse
import struct

def swap (data_in, byte_length = 4):
    if (byte_length == 2):
        return struct.pack('>H', *struct.unpack('<H', data_in))
    elif (byte_length == 4):
        return struct.pack('>I', *struct.unpack('<I', data_in))
    else:
        return 0
def strip_end (string, suffix):
    if not string.endswith(suffix):
        return string
    return string[:len(string)-len(suffix)]


if __name__ == '__main__':
    pass

parser = argparse.ArgumentParser()

# If I decide to develop further than
# needed for this assignment I want to
# implement verbose and quiet modes 

#group = parser.add_mutually_exclusive_group()
#group.add_argument("-v", "--verbose", action="store_true")
#group.add_argument("-q", "--quiet", action="store_true")
parser.add_argument("input", help="input file")
args = parser.parse_args()

pcap = open(args.input, "rb")

magic_number = pcap.read(4)
magic_hex = magic_number.encode("hex")
if (magic_hex ==  'd4c3b2a1'):
    little_endian = True
elif (magic_hex == 'a1b2c3d4'):
    little_endian = False
else:
    print "error parsing pcap"
# start creating the json string for the pcap header (first 24 bytes)   
global_header = "{\"magicNumber\": " + magic_hex

#get major version and add to global header
major_version = pcap.read(2)
if little_endian:
    major_version = swap(major_version, 2)

major_hex = major_version.encode("hex")
global_header += ", \"majorVersion\": " + str(int(major_hex, 16))

#get minor version and add to global header
minor_version = pcap.read(2)
if little_endian:
    minor_version = swap(minor_version, 2)

minor_hex = minor_version.encode("hex")
global_header += ", \"minorVersion\": " + str(int(minor_hex, 16))

#get thisZone and add to global header
this_zone = pcap.read(4)
if little_endian:
    this_zone = swap(this_zone)
    
zone_hex = this_zone.encode("hex")
global_header += ", \"thisZone\": " + str(int(zone_hex, 16))

#get sigFigs and add to global header
sig_figs = pcap.read(4)
if little_endian:
    sig_figs = swap(sig_figs)

sig_hex = sig_figs.encode("hex")
global_header += ", \"sigFigs\": " + str(int(sig_hex, 16))

#get snapLength and add to global header
snap_length = pcap.read(4)
if little_endian:
    snap_length = swap(snap_length)

snap_hex = snap_length.encode("hex")
global_header += ", \"snapLen\": " + str(int(snap_hex, 16))

#get network field and add to global
network = pcap.read(4)
if little_endian:
    network = swap(network)

net_hex = network.encode("hex")
global_header += ", \"network\": " + str(int(net_hex, 16)) + ", \"count\": "

#start reading in packet header information
count = 0
EOF = 1
packet_header = "{"
while EOF != "":
    #timestamp seconds field
    ts_sec = pcap.read(4)
    if (ts_sec == ""):
        EOF = ""
        break
    if little_endian:
        ts_sec = swap(ts_sec)
          
    ts_hex = ts_sec.encode("hex")
    packet_header += "\"" + str(count) + "\": {\"tsSec\": " + str(int(ts_hex, 16))
     
    #timestamp micro seconds field 
    ts_usec = pcap.read(4)
    if little_endian:
        ts_usec = swap(ts_usec)
          
    tsu_hex = ts_usec.encode("hex")
    packet_header += ", \"tsUSec\": " + str(int(tsu_hex, 16))
     
    # included length field
    incl_len = pcap.read(4)
    if little_endian:
        incl_len = swap(incl_len)
     
    incl_hex = incl_len.encode("hex")
    packet_header += ", \"inclLen\": " + str(int(incl_hex, 16))
     
    # original length field
    orig_len = pcap.read(4)
    if little_endian:
        orig_len = swap(orig_len)
         
    orig_hex = orig_len.encode("hex")
    packet_header += ", \"origLen\": " + str(int(orig_hex, 16)) + "}, \n"
     
    pcap.read(int(incl_hex,16))
    count += 1
     
global_header += str(count) + ",\n"
packet_header = strip_end(packet_header, ", \n")
print global_header + packet_header + "}"
pcap.close()