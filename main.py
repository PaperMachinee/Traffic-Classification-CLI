import typer
from typing_extensions import Annotated
from pathlib import Path
from ande.pipeline import PipelineError, classify_npy, preprocess_traffic


app = typer.Typer()

@app.command()
# wait
def classify(npy_path: Annotated[Path, typer.Argument(help="input your npy file path", exists=True)] = "./npy/", type: Annotated[int, typer.Option(help="Select the number(int) of categories you want to categorize ")] = 2):
    '''
    classify your traffic files to Normal or malicious. 将你的流量文件分类并辨别是否有害
    '''
    try:
        result = classify_npy(npy_path=npy_path, classify_type=type, model_dir="./model")
    except PipelineError as exc:
        raise typer.BadParameter(str(exc))

    if type == 2:
        print("The traffic may be:", result["label"])
    elif type == 14:
        print("The activity may be: ", result["label"])
    else:
        print("Not supported at this time. Waiting for perfection.")
        return
    print("Finish!")


@app.command()
def preprocess(pcap_path: Annotated[Path, typer.Argument(help="input your pcap/pcapng file path", exists = True)] = './pcap'):
    '''
    preprocess your Pcap/Pcapng file to npy file.  预处理pcap文件最终得到npy文件
    '''
#   首先判断文件类型，如果不对将之转化为一致
#  在linux下测试无问题，Windows功能后续添加
    try:
        preprocess_traffic(
            pcap_path=pcap_path,
            sessions_dir="./sessions",
            npy_dir="./npy",
            statistic_json_path="./statistic_features.json",
            trim_size=8100,
            cleanup_sessions=True,
        )
    except PipelineError as exc:
        raise typer.BadParameter(str(exc))

    print("All files are saved in ./npy folder.")
    print("Finish all operations!")




# 显示详细信息
@app.callback()
def callback():
    r'''

     ___   _   _______ _____

 / _ \ | \ | |  _  \  ___|

/ /_\ \|  \| | | | | |__  

|  _  || . ` | | | |  __| 

| | | || |\  | |/ /| |___ 

 \_| |_/\_| \_/___/ \____/  

    '''

if __name__ == "__main__" :
    app()
