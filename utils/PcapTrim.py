'''
@Author: WANG Maonan
@Date: 2021-01-05 16:48:42
@Description: 对 pcap 文件进行减裁, 使其转换为指定的大小
@LastEditTime: 2021-02-02 10:42:45
'''
import os
from rich.progress import track

def pcap_trim(pcap_folder, trimed_file_len):
    """将 pcap 文件裁剪为指定的大小

    Args:
        pcap_folder (str): pcap 文件所在的文件夹
        trimed_file_len (str): 减裁的大小
    """
    for files in track(os.listdir(pcap_folder), description="preprocessing..."):
            if not files.lower().endswith(".pcap"):
                continue
            pcap_path = os.path.join(pcap_folder, files)
            if not os.path.isfile(pcap_path):
                continue
            pcapSize = os.path.getsize(pcap_path) # 获得文件的大小, bytes

            fileLength = trimed_file_len - pcapSize # 文件大小与规定大小之间的比较
            if fileLength > 0 : # 需要进行填充
                with open(pcap_path, 'ab') as f: # 这里使用with来操作文件
                    f.write(bytes([0]*fileLength)) # 获取文件内容  
            elif fileLength < 0 : # 需要进行裁剪
                with open(pcap_path, 'ab') as f: # 这里使用with来操作文件
                    f.seek(trimed_file_len)
                    f.truncate() # 文件进行裁断
            else: # 文件大小正好是 trimed_file_len 的, 就不需要进行处理
                pass
