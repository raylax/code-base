# -*- coding: utf8 -*-

import requests
import hashlib
import re
from urllib.parse import urlencode
import json
import random
import string
import traceback

USERNAME = ""  # 用户名
PASSWORD = ""  # 密码

"""
0 = 没有安全提问
1 = 母亲的名字
2 = 爷爷的名字
3 = 父亲出生的城市
4 = 您其中一位老师的名字
5 = 您个人计算机的型号
6 = 您最喜欢的餐馆名称
7 = 驾驶执照的最后四位数字
"""
QUESTION_ID = ""
ANSWER = ""  # 答案
MAX_DNS_QUERY = 60  # 最大DNS查询次数
SEND_KEY = ""  # Server酱send key


URL_INDEX = "https://www.t00ls.net"
URL_LOGIN = URL_INDEX + "/login.html"
URL_CHECK_LOGIN = URL_INDEX + "/checklogin.html"
URL_PERSONAL = URL_INDEX + "/memcp.php"
URL_DNS_QUERY = URL_INDEX + "/domain.html"
URL_SIGN = URL_INDEX + "/ajax-sign.json"

s = requests.session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
})

def push_message(desc):
    requests.get(f"https://sctapi.ftqq.com/{SEND_KEY}.send", params={
        "title": "T00ls脚本",
        "desp": desc,
    })

def md5hex(message):
    m = hashlib.md5()
    m.update(message.encode())
    return m.hexdigest()

def get_form_hash(resp, regex="name=\"formhash\".*?value=\"(\\w+)\""):
    items = re.findall(regex, resp.text)
    return items[0] if items else None

def get_balance():
    resp = s.get(URL_PERSONAL)
    return re.findall(">TuBi:\\s+(\\d+)\\s+<", resp.text)[0]

def random_domain():
    return ''.join(random.choices(string.ascii_lowercase, k=5)) + '.' + ''.join(random.choices(["com", "cn", 'net']))

def query_dns():
    i = 1
    original_balance = get_balance()
    print("[*] 开始DNS查询 TubBi:%s" % original_balance)
    while True:
        resp = s.get(URL_DNS_QUERY)
        domain = random_domain()
        payload = {
            "domain": domain,
            "formhash": get_form_hash(resp),
            "querydomainsubmit": "查询",
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        try:
            print("[*] 尝试进行第%d次查询 %s" % (i, domain))
            s.post(URL_DNS_QUERY, data=urlencode(payload, encoding='utf8'), headers=headers, timeout=60)
            new_balance = get_balance()
            if original_balance != new_balance:
                print("[*] DNS查询成功 TuBi:%s" % new_balance)
                return
        except e:
            pass
        i += 1
        if i > MAX_DNS_QUERY:
            print("[!] 超出最大查询次数")
            return

def sign(profile_url):
    print("[*] 开始签到")
    resp = s.get(profile_url)
    form_hash = get_form_hash(resp, "WebSign\\('(\\w+)'\\)")
    if not form_hash:
        print("[-] 已签到")
        return False
    payload = {
        "formhash": form_hash,
        "signsubmit": "apply",
    }
    s.post(URL_SIGN, data=payload)
    print("[*] 签到完成 TuBi:%s" % get_balance())
    return True

def main():
    try:
        resp = s.post(URL_LOGIN)
        cookie_time = re.findall("name=\"cookietime\".*?value=\"(\\w+)\"", resp.text)[0]
        payload = {
            "username": USERNAME,
            "password": md5hex(PASSWORD),
            "questionid": QUESTION_ID,
            "answer": ANSWER,
            "redirect": URL_INDEX,
            "formhash": get_form_hash(resp),
            "cookietime": cookie_time,
            "loginsubmit": "登录",
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        print("[*] 开始登录")
        resp = s.post(URL_LOGIN, data=urlencode(payload, encoding='utf8'), headers=headers, allow_redirects=False)
        if resp.status_code != 302:
            error_message = re.findall("\"alert_message.*?>(.*?)</", resp.text)[0]
            print("[!] %s" % error_message)
            exit(-1)
        resp = s.get(URL_CHECK_LOGIN)
        name = re.findall("href=\"members.*?>(.*?)<", resp.text)[0]
        personal_url = URL_INDEX + "/" + re.findall("members-profile-\\d+\\.html", resp.text)[0]
        balance = get_balance()
        print("[*] 登录成功 %s TuBi:%s" % (name, balance))
        success = sign(personal_url)
        if not success:
            return
        query_dns()
        print("[*] 推送消息")
        push_message("执行成功 TuBi:%s" % get_balance())
    except:
        push_message("执行失败 %s" % traceback.format_exc())
        raise


if __name__ == '__main__':
    main()
