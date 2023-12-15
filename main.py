import typer
from typing_extensions import Annotated
from pathlib import Path
import os
import subprocess
import pickle
import numpy as np
import torch
from rich.progress import track
from pcap_splitter.splitter import PcapSplitter
from scapy.all import sniff, wrpcap
from utils.feature2json import statisticFeature2JSON
from utils.sessionanonymize import anonymize
from utils.PcapTrim import pcap_trim
from utils.pcap2npy import save_pcap2npy
from utils.test14 import get_tensor_data, ANDE


app = typer.Typer()

@app.command()
# wait
def classify(npy_path: Annotated[Path, typer.Argument(help="input your npy file path", exists=True)] = "./npy/", type: Annotated[int, typer.Option(help="Select the number(int) of categories you want to categorize ")] = 2):
    '''
    classify your traffic files to Normal or malicious. 将你的流量文件分类并辨别是否有害
    '''
    if type == 2:
        test_data = np.load(os.path.join(npy_path, "statistic.npy"))

        with open('./model/rf.pkl', 'rb') as file:
            loaded_model = pickle.load(file)

        prediction = loaded_model.predict(test_data)

        count = np.bincount(prediction).argmax()

        count2label = {'NORMAL': 0, 'Tor': 1}

        label = next(key for key, value in count2label.items() if value == count)

        print("The traffic may be:", label)
        print("Finish!")
    elif type == 14:    
        pcap_data, statistic_data = get_tensor_data(pcap_file='./npy/pcap.npy', statistic_file='./npy/statistic.npy')
        pcap_data =  pcap_data/255

        labelandindex = {'Browsing': 0, 'Chat': 1, 'Email': 2, 'FT': 3, 'P2P': 4, 'Streaming': 5, 'Tor_Browsing': 6, 'Tor_Chat': 7, 'Tor_Email': 8, 'Tor_FT': 9, 'Tor_P2P': 10, 'Tor_Streaming': 11, 'Tor_VoIP': 12, 'VoIP': 13}
        index2label = {j: i for i, j in labelandindex.items()}
        label_list = [index2label.get(i) for i in range(14)]

        model = ANDE('model/8100_session_mymodel.pth', pretrained=True, num_classes=14).to('cpu')

        start_index = 0
        y_pred1 = None
        for i in track(list(range(1, pcap_data.shape[0]+1, 1)), description="Validation..."): # 要一批一批的放,否则会报错
            y_pred, _ = model(pcap_data[start_index:i], statistic_data[start_index:i])  # 放入模型进行预测
            start_index = i
            if y_pred1 == None:
                y_pred1 = y_pred.cpu().detach()
            else:
                y_pred1 = torch.cat((y_pred1,y_pred.cpu().detach()),dim = 0)
                # print(y_pred1.shape)
        
        _, pred = y_pred1.topk(1, 1, largest=True, sorted=True)

        pred_label = [index2label.get(i.tolist()) for i in pred.view(-1).cpu().detach()]
        unique_strings, counts = np.unique(pred_label, return_counts=True)
        most_common_index = np.argmax(counts)
        most_common_string = unique_strings[most_common_index]

        print('The activity may be: ', most_common_string)
        print("Finish!")

    else:
        print("Not supported at this time. Waiting for perfection.")


@app.command()
def preprocess(pcap_path: Annotated[Path, typer.Argument(help="input your pcap/pcapng file path", exists = True)] = './pcap'):
    '''
    preprocess your Pcap/Pcapng file to npy file.  预处理pcap文件最终得到npy文件
    '''
#   首先判断文件类型，如果不对将之转化为一致
#  在linux下测试无问题，Windows功能后续添加
    pcap_path = Path(pcap_path)
    print(f"Now, preprocessing the files under the folder (正在预处理文件): {pcap_path.name}")
    for files in track(os.listdir(pcap_path), description="processing..."): # track进度条
        if files.split('.')[1] == 'pcapng':
            output_name = '{}.pcap'.format(files.split('.')[0])
            input_path = pcap_path / files
            output_path = pcap_path / output_name
            command = ['editcap', '-F', 'pcap', str(input_path), str(output_path)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"success! convert {files} to {output_name}")
            else:
                print("error, info:", result.stderr)

    # 将pcap文件转为session
    print(f"Now, preprocessing these files to sessions in folder (转成session): {pcap_path.name}")
    for files in track(os.listdir(pcap_path), description="processing..."):
        if files.split('.')[1] == 'pcap':
            ps = PcapSplitter(f"{pcap_path / files}")
            ps.split_by_session("sessions")
    

    # 计算pcap的统计特征
    new_path = "sessions"
    print(f"Now, extracting statistic features from {new_path}.")
    statisticFeature2JSON(new_path)
    

    # 匿名化sessions
    anonymize(new_path)

    # Trim pcap
    size = 8100
    print(f"Now, Triming them into {size} size.")
    pcap_trim(new_path, size)

    # 生成npy
    save_pcap2npy(new_path, "statistic_features.json")
    print("All files are saved in ./npy folder.")
    print(f"Now, deleting all files under {new_path}")
    for filename in track(os.listdir(new_path), description="deleting..."):
        filepath = os.path.join(new_path, filename)
        if filename.split('.')[1] == "pcap":
            os.remove(filepath)
    print("Finish all operations!")




# 显示详细信息
@app.callback()
def callback():
    '''

     ___   _   _______ _____

 / _ \ | \ | |  _  \  ___|

/ /_\ \|  \| | | | | |__  

|  _  || . ` | | | |  __| 

| | | || |\  | |/ /| |___ 

 \_| |_/\_| \_/___/ \____/  

    '''

if __name__ == "__main__" :
    app()
