from scapy.all import sendp, Raw, sniff, random
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoETag, PPP_LCP, PPPoED, PPPoE, PPP_LCP_MRU_Option, PPP_LCP_Auth_Protocol_Option, \
    PPP_LCP_Magic_Number_Option, PPP_LCP_Configure, PPP_PAP_Request, PPPoED_Tags
import RouterPost1

PPPoE_Discovery = 0x8863
PPPoE_SESSION = 0x8864
SESSION_ID = 0x0021
PADI_Code = 0x09
PADR_Code = 0x19
PADO_Code = 0x07
PADS_Code = 0x65
Host_Uniq = 0x0103
Service_Name = 0x0101
AC_Name = 0x0102
AC_Cookie = 0x0104
Configure_Request = 1
Configure_Reject = 4
Configure_Ack = 2
Configure_Nak = 3
LCP = 0xc021
PAP = 0xc023
magic_number = 0xABCDEFAA


def find_Host_uniq(pkt):
    for tag in pkt[PPPoED][PPPoED_Tags].tag_list:
        if tag.tag_type == Host_Uniq:
            return tag.tag_value


class PPPOE:
    def __init__(self):
        self.filters = "pppoed || pppoes"
        self.MacAddress = self.getMacAddress()
        self.default_user = "abcdefghijklmn123"
        self.host = "192.168.0.1"

    def getMacAddress(self):
        MacList = []
        for i in range(6):
            MacList.append("".join(random.sample("0123456789abcdef", 2)))
        return ":".join(MacList)

    def start(self):
        try:
            print("请打开NetKeeper点击登陆")
            print(self.MacAddress)
            sniff(filter=self.filters, prn=self.date)
        except RuntimeError as error:
            print(error)
            return

    def date(self, pkt):
        if pkt.haslayer(PPPoED):
            if pkt[PPPoED].code == PADI_Code:
                print("进入PADI 阶段，发送PADO")
                host_uniq = find_Host_uniq(pkt)
                sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_Discovery)
                      / PPPoED(code=PADO_Code, sessionid=pkt[PPPoED].fields['sessionid']) /
                      PPPoETag(tag_type=Service_Name, tag_value="") /
                      PPPoETag(tag_type=AC_Name, tag_value="NetKeeper") /
                      PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq), verbose=False)
            if pkt[PPPoED].code == PADR_Code:
                print("进入PADR阶段,发送PADS")
                host_uniq = find_Host_uniq(pkt)
                sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_Discovery) /
                      PPPoED(code=PADS_Code, sessionid=SESSION_ID) /
                      PPPoETag(tag_type=Service_Name, tag_value="") /
                      PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq), verbose=False)
                # 双方互相发送发送LCP
                print("开始进行LCP协商")
                sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_SESSION) /
                      PPPoE(sessionid=SESSION_ID) /
                      PPP(proto=LCP) /
                      PPP_LCP(code=Configure_Request,
                              data=(Raw(PPP_LCP_MRU_Option(max_recv_unit=1492)) /
                                    Raw(PPP_LCP_Auth_Protocol_Option(
                                        auth_protocol=PAP)) /
                                    Raw(PPP_LCP_Magic_Number_Option(
                                        magic_number=magic_number)))), verbose=False)

        elif pkt.haslayer(PPPoE) and pkt.haslayer(PPP):
            if pkt.haslayer(PPP_LCP_Configure):
                if pkt[PPP_LCP_Configure].code == Configure_Request:
                    if len(pkt.payload.options) > 3:
                        print("发送Config-Reject请求")
                        sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_SESSION) /
                              PPPoED(sessionid=SESSION_ID) /
                              PPP(proto=LCP) /
                              PPP_LCP(code=Configure_Reject, data=Raw(bytes(pkt.payload)[22:])), verbose=False)
                    sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_SESSION) /
                          PPPoE(sessionid=SESSION_ID) /
                          PPP(proto=LCP) /
                          PPP_LCP(code=Configure_Ack, id=pkt[PPP_LCP_Configure].id,
                                  data=(Raw(PPP_LCP_MRU_Option(max_recv_unit=1480)) /
                                        Raw(pkt[PPP_LCP_Configure][
                                                PPP_LCP_Magic_Number_Option]))), verbose=False)
            elif pkt.haslayer(PPP_PAP_Request):
                print("账号获取成功")
                response = pkt[PPP_PAP_Request]
                sendp(Ether(src=self.MacAddress, dst=pkt[Ether].src, type=PPPoE_SESSION) /
                      PPPoED(sessionid=SESSION_ID) /
                      PPP(proto=PAP) / b'\x031\x00\x06\x01\x00', verbose=False)
                user = response.username.decode("utf8")
                print(user)
                try:
                    password = response.password.decode("utf8")
                except AttributeError:
                    password = ""
                print(f"请打开路由器拨号页面,将拨号用户名设置为{self.default_user},密码自行填写,然后拨号")
                RouterPost1.HttpResend(self.host, self.default_user, user).start()


if __name__ == '__main__':
    PPPOE().start()
