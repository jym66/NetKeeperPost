from requests import post


class RouterPost:
    def __init__(self, user, password):
        self.url = None
        self.user = user
        self.password = password
        self.configPath = "./"
        self.headers = None
        self.params = None
        self.ReadConfig()

    def ReadConfig(self):
        try:
            with open("config.txt", "r", encoding="utf8") as file:
                content = file.read().split("\n")
        except FileNotFoundError:
            print("未检测到配置文件,将不进行路由器提交")
            return
        self.url = content[0].split(":=")[1]
        self.headers = eval(content[1].split(":=")[1])
        self.params = eval(content[2].split(":=")[1])
        # 替换配置文件里的user password
        for i in self.params.keys():
            if self.params[i] == "user":
                self.params[i] = self.user
            if self.params[i] == "password":
                self.params[i] = self.password
        self.start_post()

    def start_post(self):
        res = post(self.url, headers=self.headers, data=self.params)
        if res.status_code != 200:
            print("提交路由器失败,请检查参数")


if __name__ == '__main__':
    RouterPost("test1111", "123")
