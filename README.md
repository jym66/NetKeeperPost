# 用于本地拦截NetKeeper账号并提交到路由器

## 需要安装 [winpacp](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)

### 用到的库  Scapy
* pip install scapy
### 使用 
* python3 FakePPPoe.py 
* 记得把代码里的路由器网址改成自己的默认写的 192.168.0.1
* 路由器拨号用户名改为 abcdefghijklmn123,密码填写正确的密码即可

### 自动POST路由器原理
*  使用Scapy 获取路由器点击拨号发送的请求参数(所以需要先登陆路由器点一下拨号),然后替换请求体里的账号，在进行数据拼装发送。

### 未解决的问题 
* 1.提交之后可能不会自动拨号需要手动点一下拨号，请根据路由器联网状态自行判断.
* 2.某些路由器固件不支持\r，无法拨号.
* 3.在某些情况下可能获取到的请求体不全比如penwrt固件的(不过openwrt也用不到这个😂)