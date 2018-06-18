import pydivert
import re
import copy

host_pattern = re.compile("Host:\s([a-zA-Z0-9.-]+)")
fd = open("sorted_data_ansi.txt", "r") # type cp949(Ansi)
sites = fd.readlines()
block_sites = []
ack_num = 0
seq_num = 0
save_finack_packet = 0

def bin_search(data, cmp_text):
    low, high = 0, len(data)-1
    while low<=high:
        middle = int((low+high)/2)
        if data[middle] < cmp_text:
            low = middle + 1
        elif data[middle] > cmp_text:
            high = middle - 1
        else:
            return True
    return False

for site in sites:
    block_sites.append(site.splitlines()[0])

block_sites.sort() # bin search need sorting

with pydivert.WinDivert("tcp.DstPort == 80 or tcp.SrcPort == 80",0,0,1) as w_handle: # last flag is SNIFF MODE
    for packet in w_handle:
        isBlock = False
        if packet.ipv4:
            if packet.tcp:
                if packet.tcp.dst_port == 80:
                    payload = str(packet.payload)
                    site = host_pattern.search(payload)
                    
                    if site: # check block site
                        if bin_search(block_sites,site.group(1)):
                            isBlock = True
                            packet.tcp.syn = False
                            packet.tcp.fin = True
                            packet.tcp.ack = True

                            # use shallow-copy
                            tmp_src_ip = copy.copy(packet.src_addr)
                            tmp_dst_ip = copy.copy(packet.dst_addr)

                            tmp_ack_num = copy.copy(packet.tcp.ack_num)
                            tmp_seq_num = copy.copy(packet.tcp.seq_num)

                            tmp_src_port = copy.copy(packet.src_port)
                            tmp_dst_port = copy.copy(packet.dst_port)
                            # end

                            # swap
                            packet.src_addr = tmp_dst_ip
                            packet.dst_addr = tmp_src_ip

                            packet.ipv4.src_addr = tmp_dst_ip
                            packet.ipv4.dst_addr = tmp_src_ip

                            packet.src_port = tmp_dst_port
                            packet.dst_port = tmp_src_port

                            packet.tcp.src_port = tmp_dst_port
                            packet.tcp.dst_port = tmp_src_port

                            packet.ipv4.tos = 1 # packet_filter

                            packet.tcp.ack_num = tmp_seq_num
                            packet.tcp.ack_num = packet.tcp.ack_num + len(packet.tcp.payload)
                            packet.tcp.seq_num = tmp_ack_num
                            #packet.tcp.seq_num = tmp_ack_num
                            packet.tcp.payload = b"HTTP/1.1 302 Found\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 0\r\nLocation: http://warning.or.kr/i1.html\r\n\r\n"
                            
                            packet.direction = 1
                            #print(packet)
                            w_handle.send(packet, recalculate_checksum=True)
                    if packet.ipv4.tos == 1:
                        print(packet)
fd.close()
