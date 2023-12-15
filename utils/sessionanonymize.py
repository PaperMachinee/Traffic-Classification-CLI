import os
from scapy.all import sniff, wrpcap
from rich.progress import track

def customAction(pcap):
    """对一个 session 中的每一个 packet 进行匿名化的处理

    Args:
        pcap: 每一个 packet 文件
    """
    src_ip = "0.0.0.0"
    src_ipv6 = "0:0:0:0:0:0:0:0"
    src_port = 0
    src_mac = "00:00:00:00:00:00"

    dst_ip = "0.0.0.0"
    dst_ipv6 = "0:0:0:0:0:0:0:0"
    dst_port = 0
    dst_mac = "00:00:00:00:00:00"
    
    if 'Ether' in pcap:
        pcap.src = src_mac # 修改源 mac 地址
        pcap.dst = dst_mac # 修改目的 mac 地址
    if 'IP' in pcap:
        pcap["IP"].src = src_ip
        pcap["IP"].dst = dst_ip
    if 'IPv6' in pcap:
        pcap["IPv6"].src = src_ipv6
        pcap["IPv6"].dst = dst_ipv6
    if 'TCP' in pcap:
        pcap['TCP'].sport = src_port
        pcap['TCP'].dport = dst_port
    if 'UDP' in pcap:
        pcap['UDP'].sport = src_port
        pcap['UDP'].dport = dst_port
    if 'ARP' in pcap:
        pcap["ARP"].psrc = src_ip
        pcap["ARP"].pdst = dst_ip
        pcap["ARP"].hwsrc = src_mac
        pcap["ARP"].hwdst = dst_mac



def session_anonymize(session_path):
    """对一个 session 进行匿名化处理, 逐个处理 session 中的每一个 packet; 
    这里如果一个 pcap 较大, 会出现 MemoryError 的问题.
    可以在 sniff 的时候设置 count, 因为后面需要进行减裁, 所以不需要对 pcap 全部进行匿名化, 只需要匿名化部分就可以了
    Args:
        filePath (str): session 所在的路径
    """
    packets = sniff(offline=session_path, prn=customAction, store=True, count=10000) # 这里的数据类型是 scapy.plist.PacketList
    return packets

def anonymize(folder_path):
    """将 folder_path 中所有的 session 全部进行匿名化, 同时删除一个 session 少于 3 个 packet 的 session

    Args:
        folder_path (str): 所在的路径
    """
    print('anonymizing the packets. 正在匿名化 {} 下的 pcap 文件'.format(folder_path))
    for files in track(os.listdir(folder_path), description="processing..."):
        # for Ufile in files:
        pcapPath = os.path.join(folder_path, files) # 需要转换的pcap文件的完整路径
        packets = session_anonymize(pcapPath) # 匿名化 session
        os.remove(pcapPath) # 删除原始的 pcap 文件
        if len(packets)>3: # 如果一个 session 中 packet 的个数较少, 就不保存
            wrpcap(pcapPath, packets) # 保存新的 pcap 文件
    # print("Finish!")