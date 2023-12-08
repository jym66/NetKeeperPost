import socket
from scapy.all import sniff
from scapy.layers.http import HTTPRequest, HTTP
from scapy.sessions import TCPSession
from scapy.supersocket import StreamSocket
from time import sleep
from urllib.parse import quote
#对用户名进行url编码，避免获取到真实的用户名掺杂特殊字符提交失败，特殊字符包括但不限于空格，方括号，星号，and符号等

class HttpResend:
    def __init__(self, host, default_user, username):
        self.host = host
        self.port = 80
        self.filter = f"host {self.host} and tcp and port 80"
        self.default_user = default_user
        self.username = username
        self.stopFlag = False

    def start(self):
        sniff(filter=self.filter, prn=self.parse, session=TCPSession, stop_filter=self.stop)
        return

    def stop(self, x):
        return self.stopFlag

    def getUser(self):
        # 用户名加密的话可以在这里改
        return self.default_user

    def parse(self, pkt):
        # 解析HTTP协议
        if pkt.haslayer(HTTPRequest) and str(pkt.getlayer("Raw")).find(self.getUser()) != -1:
            # URL编码用户名
            encoded_username = quote(self.username)
            body = bytes(pkt.getlayer("Raw")).decode().replace(self.default_user, encoded_username)
            print("已获取路由器发送的 HTTP 请求体,开始重新组装数据")
            if pkt[HTTPRequest].fields.get('Content_Length') is not None:
                pkt[HTTPRequest].fields['Content_Length'] = str(len(body)).encode()
            request = HTTP() / HTTPRequest(
                # 通用请求头
                Method=pkt[HTTPRequest].fields.get('Method'),
                Path=pkt[HTTPRequest].fields.get('Path'),
                Accept=pkt[HTTPRequest].fields.get('Accept'),
                Accept_Encoding=pkt[HTTPRequest].fields.get('Accept_Encoding'),
                Accept_Language=pkt[HTTPRequest].fields.get('Accept_Language'),
                Cache_Control=pkt[HTTPRequest].fields.get('Cache_Control'),
                Connection=pkt[HTTPRequest].fields.get('Connection'),
                Content_Length=pkt[HTTPRequest].fields.get('Content_Length'),
                Content_Type=pkt[HTTPRequest].fields.get('Content_Type'),
                Host=pkt[HTTPRequest].fields.get('Host'),
                Origin=pkt[HTTPRequest].fields.get('Origin'),
                Pragma=pkt[HTTPRequest].fields.get('Pragma'),
                Referer=pkt[HTTPRequest].fields.get('Referer'),
                User_Agent=pkt[HTTPRequest].fields.get('User_Agent'),
                Cookie=pkt[HTTPRequest].fields.get('Cookie'),
                Authorization=pkt[HTTPRequest].fields.get('Authorization'),
            ) / body
            print("数据组装完毕,开始重新发送拨号请求")
            sleep(1)  # 等一秒发送, 要不然发送太快可能不生效
            response = self.send_requests(request)
            print("发送完毕 状态码: " + response.getlayer("HTTPResponse").fields.get("Status_Code").decode() + " 请自行查看拨号是否成功")
            self.stopFlag = True

    def send_requests(self, byte_data):
        s = socket.socket()
        s.connect((self.host, self.port))
        sock = StreamSocket(s, HTTP)
        return sock.sr1(byte_data, verbose=False)


if __name__ == '__main__':
    HttpResend("192.168.0.156", "123", "password").start()
