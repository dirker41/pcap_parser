import sys
import os
#import pyshark

MAC_LEN=12
SVLAN_LEN=0
CVLAN_LEN=0
MEF8_LEN=10
RTP_HEADER_LAN=12
RTP_HEADER_TS_SHIFT=-8

PCAP_PKT_HEADER_LEN=16

#FILE_NAME="G7800_32TE1_DCR.pcap"
TS_OFFSET=MAC_LEN+SVLAN_LEN+CVLAN_LEN+MEF8_LEN+RTP_HEADER_LAN+RTP_HEADER_TS_SHIFT


def bytes_match(bytes1, bytes2):

    #print(hex(bytes1[0]), hex(bytes1[1]), hex(bytes1[2]), hex(bytes1[3]), hex(bytes1[4]), hex(bytes1[5]))
    #print(hex(bytes2[0]), hex(bytes2[1]), hex(bytes2[2]), hex(bytes2[3]), hex(bytes2[4]), hex(bytes2[5]))

    for index in range(len(bytes1)):
        if(bytes1[index]!=bytes2[index]):
            return 0
        
    return 1


def byte_reverse_sum(bytes, len):
    sum=0
    
    for index in range(1, len+1):
        #print("[%d]=%d"%(len-index, int(bytes[len-index])))
        sum=sum*256 + bytes[len-index]
        
    return sum
    
def byte_sum(bytes, len):
    sum=0
    
    for index in range(len):
        #print("[%d]=%d"%(len-index, bytes[len-index]))
        sum=sum*256 + bytes[index]
        
    return sum


def get_global_header(bytes):
  magic_number=byte_reverse_sum(bytes[0:], 4)
  version_major=byte_reverse_sum(bytes[4:], 4)
  version_minor=byte_reverse_sum(bytes[6:], 4)
  thiszone=byte_reverse_sum(bytes[8:], 4)
  sigfigs=byte_reverse_sum(bytes[12:], 4)
  snaplen=byte_reverse_sum(bytes[16:], 4)
  network=byte_reverse_sum(bytes[20:], 4)
  
  
    
def get_packet_header(bytes):
    
    ts_sec=byte_reverse_sum(bytes[0:], 4)
    ts_usec=byte_reverse_sum(bytes[4:], 4)
    incl_len=byte_reverse_sum(bytes[8:], 4)
    orig_len=byte_reverse_sum(bytes[12:], 4)
    
    #print("ts_sec:%d"%ts_sec)
    #print(ts_usec)
    #print(incl_len)
    #print(orig_len)
    
    return ts_sec, ts_usec, incl_len, orig_len
    
    
def get_packet(bytes):
    ts_sec, ts_usec, incl_len, orig_len=get_packet_header(bytes)
    data=bytes[PCAP_PKT_HEADER_LEN:PCAP_PKT_HEADER_LEN+incl_len]
    
    return ts_sec, ts_usec, incl_len, orig_len, data

def skip_pkt(pkt, incl_len=0):
    #if(incl_len==243):
    #    return 1
    src_mac=bytes([0x00, 0x20, 0x18, 0x06, 0x25, 0x10])

    if(incl_len==227):
        return 1

    #if(!bytes_match(src_mac, pkt[6:12])):
    #    return 1
    
    return 0

def print_bytes(bytes):
    for b in bytes:
        print(hex(b))

def bytes_str(bytes):
    ret_str=""
    for b in bytes:
        ret_str+=":"+(hex(b)[2:]).zfill(2)

    return ret_str
    


argc = len(sys.argv)
if(argc==2):
    FILE_NAME=sys.argv[1]

print("parse file:"+sys.argv[1])

f=open(FILE_NAME, "rb")
pcap=f.read()
f.close()

get_global_header(pcap)

index=24

tmp_ts=0

std_dif=0
no=0
tmp_no=0
print("ts_offset:"+ str(TS_OFFSET))

while index<len(pcap):
    no+=1
    #print(index)
    ts_sec, ts_usec, incl_len, orig_len, data=get_packet(pcap[index:])
    index+=incl_len+PCAP_PKT_HEADER_LEN

    if(skip_pkt(data, incl_len=incl_len)):
        #print("[%d] skip "% (no))
        continue
    tmp_no+=1

    ts=byte_sum(data[TS_OFFSET:], 4)
    if(tmp_no==1):
        tmp_ts=ts
        print("ts_offset:"+ str(TS_OFFSET))
        print("first ts:" + str(hex(ts)))
        print("dst_mac"+bytes_str(data[0:6]))
        print("src_mac"+bytes_str(data[6:12]))
        continue

    if(tmp_no==2):
        std_dif=ts-tmp_ts
        print("std_dif:" + str(std_dif))
        if(std_dif==0):
            print("std_dif is 0, please check ts_offset")
            exit()
        tmp_ts=ts
        continue

    dif=ts-tmp_ts

    if(dif>(1.1*std_dif) or 
        dif<(0.9*std_dif) or 
        dif < 0 ):
        print("[%d] dif:%d %s %s"% (no, dif, hex(ts), hex(tmp_ts)))

    #print("[%d] dif:%d %s %s"% (no, dif, hex(ts), hex(tmp_ts)))

    #if(no%100)==0:
    #    print("[%d]"%no)

    tmp_ts=ts

    #if(no>=10):
    #    exit()