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
# Change magic number to decimal for full credit even though I prefer
# the hex as it is easier to spot endiness
#if I decide to use this code again uncomment the magic hex line and 
# comment out the Magic_dec line.   
#global_header = "{\"magicNumber\": " + magic_hex
if little_endian:
    magic_number = swap(magic_number)
magic_hex = magic_number.encode("hex")
magic_dec = int(magic_hex,16)
global_header = "{\n\t\"magicNumber\": " + str(magic_dec)
#get major version and add to global header
major_version = pcap.read(2)
if little_endian:
    major_version = swap(major_version, 2)

major_hex = major_version.encode("hex")
global_header += ",\n\t\"majorVersion\": " + str(int(major_hex, 16))

#get minor version and add to global header
minor_version = pcap.read(2)
if little_endian:
    minor_version = swap(minor_version, 2)

minor_hex = minor_version.encode("hex")
global_header += ",\n\t\"minorVersion\": " + str(int(minor_hex, 16))

#get thisZone and add to global header
this_zone = pcap.read(4)
if little_endian:
    this_zone = swap(this_zone)
    
zone_hex = this_zone.encode("hex")
global_header += ",\n\t\"thisZone\": " + str(int(zone_hex, 16))

#get sigFigs and add to global header
sig_figs = pcap.read(4)
if little_endian:
    sig_figs = swap(sig_figs)

sig_hex = sig_figs.encode("hex")
global_header += ",\n\t\"sigFigs\": " + str(int(sig_hex, 16))

#get snapLength and add to global header
snap_length = pcap.read(4)
if little_endian:
    snap_length = swap(snap_length)

snap_hex = snap_length.encode("hex")
global_header += ",\n\t\"snapLen\": " + str(int(snap_hex, 16))

#get network field and add to global
network = pcap.read(4)
if little_endian:
    network = swap(network)

net_hex = network.encode("hex")
global_header += ",\n\t\"network\": " + str(int(net_hex, 16)) + ",\n\t\"count\": "

#start reading in packet header information
count = 0
EOF = 1
record_header = ""
while EOF != "":
    #timestamp seconds field
    ts_sec = pcap.read(4)
    if (ts_sec == ""):
        EOF = ""
        break
    if little_endian:
        ts_sec = swap(ts_sec)
          
    ts_hex = ts_sec.encode("hex")
    record_header += "\t\"" + str(count) + "\": {\n\t\t\"tmSec\": " + str(int(ts_hex, 16))
     
    #timestamp micro seconds field 
    ts_usec = pcap.read(4)
    if little_endian:
        ts_usec = swap(ts_usec)
          
    tsu_hex = ts_usec.encode("hex")
    record_header += ", \n\t\t\"tmUSec\": " + str(int(tsu_hex, 16))
     
    # included length field
    incl_len = pcap.read(4)
    if little_endian:
        incl_len = swap(incl_len)
     
    incl_hex = incl_len.encode("hex")
    record_header += ", \n\t\t\"inclLen\": " + str(int(incl_hex, 16))
     
    # original length field
    orig_len = pcap.read(4)
    if little_endian:
        orig_len = swap(orig_len)
         
    orig_hex = orig_len.encode("hex")
    record_header += ", \n\t\t\"origLen\": " + str(int(orig_hex, 16)) + ", \n"
    
    ethr_header = ""
    ### start ethernet header 6 bytes for dest, 6 bytes for source and 2 bytes for ether type (value of ip type is 0x800
    ethr_header += "\t\t\"ethHdr\": {\n\t\t\t\"dst\": \""
    for i in range(0,6):
        next_byte = pcap.read(1)
        next_byte_hex = next_byte.encode("hex")
        ethr_header += str(next_byte_hex) + "::"
    
    ethr_header = strip_end(ethr_header, "::")
    ethr_header += "\",\n\t\t\t\"src\": \""
    for i in range(0,6):
        next_byte = pcap.read(1)
        next_byte_hex = next_byte.encode("hex")
        ethr_header += str(next_byte_hex) + "::"
        
    ethr_header = strip_end(ethr_header, "::")
    ethr_header += "\",\n\t\t\t\"type\": \"0x"
    pkt_type = pcap.read(2)
    pkt_type_hex = pkt_type.encode("hex")
    ethr_header += str(pkt_type_hex) + "\"\n\t\t},\n"
    
    ### END Ether header
    ## add logic to throw out non ip packets (type is not 0x800)
    if int(pkt_type_hex) != 800:
        pcap.read(int(incl_hex,16)-14)
        record_header += ethr_header
        count += 1
        continue
     
    ### START IP Header parse
    ip_header = ""
    # Version and IHL (header length)
    ver_hdr_lngth = pcap.read(1)
    ver_hdr_lngth_hex = ver_hdr_lngth.encode("hex") 
    version = int(ver_hdr_lngth_hex, 16) / 16
    headerLen = int(ver_hdr_lngth_hex, 16) % 16  
    
    service_type = pcap.read(1)
    service_type_hex = service_type.encode("hex")
    typeOfService = int(service_type_hex, 16)
    
    total_len = pcap.read(2)
    total_len_hex = total_len.encode("hex")
    totalLen = int(total_len_hex, 16)
    
    ip_id = pcap.read(2)
    id_hex = ip_id.encode("hex")
    totalId = int(id_hex, 16)
    
    # Flags and fragment offset flags are 3 bits and offset is 13
    flag_offset = pcap.read(2)
    flag_offset_hex = flag_offset.encode("hex")
    flags = int(flag_offset_hex, 16) / 8192
    flags = hex(flags)
    fragmentOffset = int(flag_offset_hex, 16) % 8192
    
    ttl = pcap.read(1)
    ttl_hex = ttl.encode("hex")
    timeToLive = int(ttl_hex, 16)
    
    proto = pcap.read(1)
    proto_hex = proto.encode("hex")
    protocol = int(proto_hex, 16)
    
    hdr_chk = pcap.read(2)
    checksum = hdr_chk.encode("hex")
    
    ## assemble string for ip header before adding source and dest addresses
    ip_header += "\t\t\"ip4Hdr\": {\n\t\t\t\"version\": " + str(version) + ",\n\t\t\t\"headerLen\": " + str(headerLen)
    ip_header += ",\n\t\t\t\"typeOfService\": " + str(typeOfService) + ",\n\t\t\t\"totalLen\": " + str(totalLen)
    ip_header += ",\n\t\t\t\"totalId\": " + str(totalId) + ",\n\t\t\t\"flags\": \"" + flags + "\""
    ip_header += ",\n\t\t\t\"fragmentOffset\": " + str(fragmentOffset) + ",\n\t\t\t\"timeToLive\": " + str(timeToLive)
    ip_header += ",\n\t\t\t\"protocol\": " + str(protocol) + ",\n\t\t\t\"checksum\": \"0x" + str(checksum) + "\","
    
    ip_header += "\n\t\t\t\"src\": \""
    for i in range(0,4):
        next_byte = pcap.read(1)
        next_byte_hex = next_byte.encode("hex")
        next_byte_int = int(next_byte_hex, 16)
        ip_header += str(next_byte_int) + "."
    
    ip_header = strip_end(ip_header, ".")
    ip_header += "\",\n\t\t\t\"dst\": \""
    for i in range(0,4):
        next_byte = pcap.read(1)
        next_byte_hex = next_byte.encode("hex")
        next_byte_int = int(next_byte_hex, 16)
        ip_header += str(next_byte_int) + "."
        
    ip_header = strip_end(ip_header, ".")
    ip_header += "\""
    
    
    ip_header += "\n\t\t}, \n"
    
    ## If it isnt a tcp packet we are done  and need to assemble string and loop through
    if protocol != 6:
        pcap.read(int(incl_hex,16)-34)
        ip_header = strip_end(ip_header, ", \n") + "\n"
        record_header += ethr_header + ip_header + "\t}, \n" 
        count += 1  
        continue
    
    #if the ipheader has options we need to read those off before getting to the tcp header
    if headerLen == 6:
        pcap.read(4)
    
    if protocol == 6:
        tcp_header = ""
        source_port = pcap.read(2)
        srcPort = int(source_port.encode("hex"), 16)
        
        dest_port = pcap.read(2)
        dstPort = int(dest_port.encode("hex"), 16)
        
        sequence_num = pcap.read(4)
        seqNum = int(sequence_num.encode("hex"), 16)
        
        ack_num = pcap.read(4)
        ackNum = int(ack_num.encode("hex"), 16)
        
        #first 4 bits are offset second 4 are reserved
        tcp_offset = pcap.read(1)
        offset = int(tcp_offset.encode("hex"), 16) / 16
        
        tcp_flag = pcap.read(1)
        tcpFlags = int(tcp_flag.encode("hex"), 16)
        
        win = pcap.read(2)
        tcpWindow = int(win.encode("hex"), 16)
        
        tcp_check = pcap.read(2)
        tcpChecksum = int(tcp_check.encode("hex"), 16)
        
        urgent_pointer = pcap.read(2)
        urgentPtr = int(urgent_pointer.encode("hex"), 16)
        
        ## Assemble TCP header string
        tcp_header += "\t\t\"tcpHdr\": {\n\t\t\t\"srcPort\": " + str(srcPort) + ",\n\t\t\t\"dstPort\": " + str(dstPort)
        tcp_header += ",\n\t\t\t\"seqNum\": " + str(seqNum) + ",\n\t\t\t\"ackNum\": " + str(ackNum)
        tcp_header += ",\n\t\t\t\"offset\": " + str(offset) + ",\n\t\t\t\"flags\": " + str(tcpFlags)
        tcp_header += ",\n\t\t\t\"window\": " + str(tcpWindow) + ",\n\t\t\t\"checksum\": " + str(tcpChecksum)
        tcp_header += ",\n\t\t\t\"urgentPtr\": " + str(urgentPtr) + "\n\t\t}\n"
        
    #read the included length of the ip packet to get to the next pcap packet header
    #TODO Keep track of length of IP packet after the header is removed so bytes can be read in to
    #continue working through the file
    if headerLen == 6:
        pcap.read(int(incl_hex,16)-58)
    if headerLen == 5:
        pcap.read(int(incl_hex,16)-54) 
    
    
    record_header += ethr_header + ip_header + tcp_header + "\t}, \n" 
    count += 1
     
global_header += str(count) + ",\n"
record_header = strip_end(record_header, ", \n")
print global_header + record_header + "\n}"
pcap.close()