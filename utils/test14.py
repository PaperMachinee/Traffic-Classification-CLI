'''
@Author: WANG Maonan PaperMachinee
@Description: SE-ResNet 与 AutoEncoder 的结合, 同时使用统计特征与原始流量, 并进行特征提取
'''
import torch
import numpy as np
import math
import torch
import torch.nn as nn
import torch.nn.functional as F

def get_tensor_data(pcap_file, statistic_file, trimed_file_len=8100):
    """读取处理好的 npy 文件, 并返回 pytorch 训练使用的 dataloader 数据

    Args:
        pcap_file (str): pcap 文件转换得到的 npy 文件的路径
        statistic_file (str): 统计特征转换得到的 npy 文件的路径
        label_file (str): 上面的 pcap 文件对应的 label 文件的 npy 文件的路径
        trimed_file_len (int): pcap 被裁剪成的长度
    """
    # 载入 npy 数据
    pcap_data = np.load(pcap_file) # 获得 pcap 文件
    statistic_data = np.load(statistic_file)

    # 将 npy 数据转换为 tensor 数据
    pcap_data = torch.from_numpy(pcap_data.reshape(-1, 1, trimed_file_len)).float()
    statistic_data = torch.from_numpy(statistic_data).float()
    print('Input Tensor data, pcap files: {}; statistic files: {}'.format(pcap_data.shape, statistic_data.shape))

    return pcap_data, statistic_data




def conv1x3(in_planes, out_planes, stride=1):
    """1x3 convolution with padding"""
    return nn.Conv1d(in_planes, out_planes, kernel_size=3, stride=stride, padding=1, bias=False)

class SEBlock(nn.Module):
    """Squeeze-and-Excitation Block
    """
    def __init__(self, channel, reduction=16):
        super(SEBlock, self).__init__()
        self.avg_pool = nn.AdaptiveAvgPool2d(1) #全局平均池化
        self.fc = nn.Sequential(
            nn.Linear(channel, channel // reduction, bias=False), # 
            nn.ReLU(inplace=True),
            nn.Linear(channel // reduction, channel, bias=False),
            nn.Sigmoid() #将权重限制到0 和 1 之间
        )

    def forward(self, x):
        # # 检查输入x的维度是否为四维
        # if x.dim() != 4:
        #     x = x.unsqueeze(3)

        # # 扩展输入x的维度为四维
        # if x.size(2) == 1 and x.size(3) == 1:
        #     x = x.view(x.size(0), x.size(1))
        #     x = x.unsqueeze(2).unsqueeze(3)
        
        b, c, _ = x.size()
        y = F.adaptive_avg_pool1d(x, 1).view(b, c) #这个函数可以自动计算输出形状，并返回形状为[batch_size, channels, 1]的张量。然后，我们使用view操作将其转换为形状为[batch_size, channels]的张量，并继续执行SEBlock的其余部分。
        # y = self.avg_pool(x).view(b, c)
        y = self.fc(y).view(b, c, 1)
        return x * y.expand_as(x)

class BasicBlock(nn.Module):
    """一个基础的 Residual Block
        添加SEblock增强性能
    """
    expansion = 1

    def __init__(self, inplanes, planes, stride=1, downsample=None):
        super(BasicBlock, self).__init__()
        self.conv1 = conv1x3(inplanes, planes, stride)
        self.bn1 = nn.BatchNorm1d(planes)
        self.relu = nn.ReLU(inplace=True)
        self.conv2 = conv1x3(planes, planes)
        self.bn2 = nn.BatchNorm1d(planes)
        #  添加SEblock
        self.se = SEBlock(planes)
        self.downsample = downsample # 是否改变输入图片的通道个数
        self.stride = stride

    def forward(self, x):
        residual = x

        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)

        out = self.conv2(out)
        out = self.bn2(out)

        if self.downsample is not None:
            residual = self.downsample(x)
        # print(out.shape)
        out = self.se(out) ##   添加SEblock
        
        out += residual
        out = self.relu(out)

        return out


class ResNet(nn.Module):
    def __init__(self, block, layers, image_width=28):
        """构建一个 ResNet
        
        Args:
            block: ResNet 中基础的 Block, 例如可以是上面定义的 BasicBlock
            layers (list): 每一块中 Block 的个数

        """
        super(ResNet, self).__init__()
        self.image_width = image_width # 处理图像的大小

        self.inplanes = 32 # 这个是经过最上面的「卷积」之后的 pannel
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=32, kernel_size=9, stride=1, padding=4, bias=False)
        self.bn1 = nn.BatchNorm1d(32)
        self.relu = nn.ReLU(inplace=True)

        self.layer1 = self._make_layer(block, 32, layers[0])
        self.layer2 = self._make_layer(block, 64, layers[1], stride=2)
        self.layer3 = self._make_layer(block, 128, layers[2], stride=2)
        self.layer4 = self._make_layer(block, 256, layers[3], stride=2)

        self.adaptiveAvgpool = nn.AdaptiveAvgPool1d(1)

        for m in self.modules(): # 对模型的参数进行初始化
            if isinstance(m, nn.Conv1d):
                n = m.kernel_size[0] * m.out_channels # 计算
                m.weight.data.normal_(0, math.sqrt(2. / n))
            elif isinstance(m, nn.BatchNorm1d):
                m.weight.data.fill_(1)
                m.bias.data.zero_()

    def _make_layer(self, block, planes, blocks, stride=1): # 所谓的残差模块
        downsample = None
        if stride != 1 or self.inplanes != planes * block.expansion:
            downsample = nn.Sequential(
                nn.Conv1d(self.inplanes, planes * block.expansion, kernel_size=1,
                          stride=stride, bias=False),
                nn.BatchNorm1d(planes * block.expansion),
            )

        layers = []
        layers.append(block(self.inplanes, planes, stride, downsample))
        self.inplanes = planes * block.expansion
        for i in range(1, blocks):
            layers.append(block(self.inplanes, planes))

        return nn.Sequential(*layers)

    def forward(self, x):
        x = x.view(x.size(0), 1, -1) # 将图像数据全部展开
        x = self.conv1(x) # (batchsize, 1, 784)->(batchsize, 32, 784)
        x = self.bn1(x)
        x = self.relu(x)
        
        x = self.layer1(x) # (batchsize, 32, 784)->(batchsize, 32, 784)
        x = self.layer2(x) # (batchsize, 32, 784)->(batchsize, 64, 364)
        x = self.layer3(x) # (batchsize, 64, 364)->(batchsize, 128, 182)
        x = self.layer4(x) # (batchsize, 128, 182)->(batchsize, 256, 91)
        
        x = self.adaptiveAvgpool(x) # (batchsize, 256, 91)->(batchsize, 256, 1)
        x = x.view(x.size(0), -1) # (batchsize, 256, 1)->(batch_size, 256)
        
        return x

class AutoEncoder_statistic(nn.Module):
    """将统计特征进行压缩
    """
    def __init__(self) -> None:
        super(AutoEncoder_statistic, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(26, 18),
            nn.ReLU(True),
            nn.Linear(18, 9),
        )

        self.decoder = nn.Sequential(
            nn.Linear(9, 18),
            nn.ReLU(True),
            nn.Linear(18, 26)
        )
    
    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)

        return x

class ResNetAE(nn.Module):
    """将两种类型的特征进行合并
    """
    def __init__(self, resnet, autoencoder, num_classes=12) -> None:
        super(ResNetAE, self).__init__()
        self.resnet = resnet
        self.autoencoder = autoencoder

        self.combine = nn.Sequential(
            nn.Linear(256+9, 100),
            nn.ReLU(),
            nn.Linear(100, 30)
        )

        self.classific = nn.Linear(30, num_classes)
    
    def forward(self, rawPcap, statistic):
        image_feature = self.resnet(rawPcap) # output, (batch size, 256)
        statistic_feature = self.autoencoder.encoder(statistic) # output, (batch size, 9)
        mixedFeature = torch.cat((image_feature, statistic_feature), dim=1) # output, (batch size, 265)
        resultVisual = self.combine(mixedFeature) # output, (batch size, 30), 这个是用来做降维可视化的

        fake_statistic = self.autoencoder.decoder(statistic_feature) # output, (batch size, 26), 还原回来的统计特征
        result = self.classific(resultVisual) # 最后的分类结果

        return result, fake_statistic

def ANDE(model_path, pretrained=False, **kwargs):
    """Constructs a ResNet-18 model.

    Args:
        pretrained (bool): If True, returns a model pre-trained on ImageNet
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    resNet_model = ResNet(BasicBlock, [2, 2, 2, 2])
    ae_model = AutoEncoder_statistic()
    resnetAE_model = ResNetAE(resnet=resNet_model, autoencoder=ae_model, **kwargs)

    if pretrained:
        checkpoint = torch.load(model_path, map_location=device) # 模型加载的时候需要注明是使用 GPU 还是 CPU
        resnetAE_model.load_state_dict(checkpoint['state_dict'])
    return resnetAE_model


