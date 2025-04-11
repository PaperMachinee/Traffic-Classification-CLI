'''
@Author: WANG Maonan
@Date: 2021-02-05 10:27:13
@Description: 计算原始 pcap 的统计特征, 并保存为 json 文件
@LastEditTime: 2021-02-05 18:11:39
'''
import os
import json
from scapy.all import rdpcap
from rich.progress import track
from utils.FeatureCalc import FeaturesCalc

def statisticFeature2JSON(folder_path):
    """将 folder_path 中所有的 session 计算统计特征, 并保存为 json 文件; 
    对于一些较大的 pcap 文件, 为了速度, 我们都只处理前 500000 个 packets

    Args:
        folder_path (str): 所在的路径
    """
    pcap_statisticFeature = {}
    featuresCalc = FeaturesCalc(min_window_size=1) # 初始化计算统计特征的类
    for files in track(os.listdir(folder_path), description="preprocessing..."):
        print('extracting statistic feature from {} .'.format(folder_path))
        pcapPath = os.path.join(folder_path, files) # 需要转换的pcap文件的完整路径
        packets = rdpcap(pcapPath) # 读入 pcap 文件
        if len(packets) < 500000: # 太大的 pcap 文件
            features = featuresCalc.compute_features(packets_list=packets) # 计算特征
        else:
            print('此文件过大，正在处理前500000字节的 {} 文件'.format(pcapPath))
            features = featuresCalc.compute_features(packets_list=packets[:500000])
        pcap_statisticFeature[files] = features
    
        # 将统计特征写入 json 文件
    with open("statistic_features.json", "w") as f:
        json.dump(pcap_statisticFeature, f)