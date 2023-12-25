<h1 align="center">
  <br>ANDE<br>
</h1>
<h4 align="center">The cli tool help you with the traffic analysis</h4>

## Features
- preprocessing the traffic raw data before classifying (now only support `*.pcap` and `*.pcapng`), if you input  `*.pcapng`  and help you reshape to `*.pcap`

- define your input traffic package and support two types of classification(2 or 14). 2 means classify your traffic as benign or malicious, 14 means user behaviors' classification. 

## Support OS

Now, only support **Linux** and **macOS**. If you use **Windows**, It's fine to use **WSL** or **virtual machine**(Vmware or virtual box).   
***support 🐳Docker already.***

## Install(Recommend)

### other needed packages

**editcap**
```bash
sudo apt install wireshark
```

**pcap-splitter**

For Pcap-splitter to work, the installation of the suite **PcapPlusPlus** is required in the system. To carry out the installation, you can follow the set of steps detailed below or make use of the [installation manual](https://pcapplusplus.github.io/docs/install).


```bash
# Just for example to install, we recommend you to read the mannual about PcapPlusPlus.
sudo apt-get install libpcap-dev
git clone https://github.com/seladb/PcapPlusPlus.git
./configure-linux.sh
make all
sudo make install
```

we recommend you create your virtual enviorment with python 3.9+

```bash
# For example with conda
conda create -n env_name python=3.9
```


```python
# install packages the project need
pip install -r requirements.txt
```

## User Manual
**This command will show all usage information about this program.**

```python
python main.py --help
```

**⚠️recommend you delete the `.gitkeep` in any folder, it may cause forseeable bug, because I haven't perfected file type recognition.**

**PR and useful issues are welcome!**

**If you like this project, welcome to give this project a star 💖.**
 
## Acknowledgment
Thanks for these open-source projects or tools!

- [editcap](https://www.wireshark.org/docs/man-pages/editcap.html)
- [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus)
- [Pcap-splitter](https://github.com/shramos/pcap-splitter)
- [Traffic-Classification](https://github.com/wmn7/Traffic-Classification)
- [Typer](https://github.com/tiangolo/typer)

