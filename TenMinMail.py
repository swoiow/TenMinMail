#!/usr/bin/env python
# -*- coding: utf-8 -*

import re
from html.parser import HTMLParser

import requests

_DEFAULT_HEADER = [
    ('Connection', 'keep-alive'),
    ('Accept-Encoding', 'gzip, deflate'),
    ('Accept-Language', 'zh-CN,zh;q=0.8'),
    ('Cache-Control', 'no-cache'),
    ('DNT', '1'),
    ('User-Agent',
     'Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.64 Safari/537.36')
]


class API(object):
    MAIL = "https://10minutemail.net/"
    MAIL_BOX = MAIL + "mailbox.ajax.php"
    MAIL_READ = MAIL + "readmail.html?mid="
    MAIL_RECOVER = MAIL + "recover.html"


def generate_pwd(rlength=16):
    import os, hashlib
    return hashlib.md5(os.urandom(rlength)).hexdigest()


class TenMinMail(API):
    def __init__(self, proxy=None):
        client = requests.Session()
        client.headers = dict(_DEFAULT_HEADER)

        if proxy:
            client.proxies = proxy

        self._client = client
        self._mail_addr = None
        self._mailbox = {}

    @property
    def client(self):
        return self._client

    @property
    def email(self):
        return self._mail_addr

    @property
    def messages(self):
        return self._mailbox

    @property
    def cookies(self):
        return self.client.cookies.items()

    def generate(self):
        resp = self.client.get(self.MAIL)

        if resp.status_code in ["200", 200]:
            html = resp.text
            rule = re.compile(r'(?<=value=")[-.\w]{3,}@[-\w]+\.[-\w]+', re.MULTILINE)

            self._mail_addr = re.findall(rule, html)[0]
            return self.email

        else:
            return False

    def mailbox(self):
        resp = self.client.get(self.MAIL_BOX)
        rule = re.compile(r"readmail.html\?mid=((?!welcome)\w+)")

        if resp.status_code in ["200", 200]:
            html = resp.text
            mail_list = re.findall(rule, html)

            for item_mail in set(mail_list):
                print(item_mail.center(50, "="))
                self._read_mail(item_mail)

        return

    def _read_mail(self, link):
        bucket = {}
        resp = self.client.get(self.MAIL_READ + link)

        html = resp.text

        dom = [
            ("title", ("h2", "class", "emoji_parse")),
            ("header", ("div", "class", "mail_headerinfo")),
            ("body", ("div", "class", "tab_content")),
        ]

        for k, v in dom:
            parser = HTMLSeeker(check_dom=v, split_char=" | ")
            parser.feed(html)

            result = parser.data
            print("{attr}: \n"
                  "{value}"
                  "\n----------\n".format(attr=k, value=result))

            bucket[k] = result

        self._mailbox[link] = bucket
        return bucket

    def to_cache(self):
        pass
        # with open()

    def restore(self, cookies):
        self.client.cookies.update(cookies)
        resp = self.client.get(self.MAIL_RECOVER)

        return resp.status_code

    addr = email


class HTMLSeeker(HTMLParser):
    def __init__(self, check_dom=(), dom_attr=(False, None), get_children=True, split_char=""):
        """
        :param check_dom: tag, attr, value
        """
        super(HTMLSeeker, self).__init__()
        self._tag, self._attr, self._value = check_dom
        self.data = ""
        self.__find__ = False
        self.get_children = get_children
        self._split_char = split_char

        if dom_attr:
            self.dom_attr, self.dom_attr_name = dom_attr
            self.dom_attr_value = ""

    def handle_starttag(self, tag, attrs):
        gid = dict(attrs).get(self._attr, "")
        if all([gid.find(self._value) > -1, tag == self._tag]):
            self.__find__ = True

            if self.dom_attr:
                self.dom_attr_value = dict(attrs).get(self.dom_attr_name)

    def handle_data(self, data):
        if self.__find__:
            if self.get_children:
                self.data += (data.strip() + self._split_char)
            else:
                self.data = data.strip()

    def handle_endtag(self, tag):
        if tag == self._tag:
            self.__find__ = False


if __name__ == '__main__':
    mail = TenMinMail()
    mail.restore(cookies=dict([('__cfduid', 'dbfd267736adad7a70f1ee7200d160fd61528906873'), ('NB_SRVID', 'srv301848'),
                               ('PHPSESSID', 'd8376b4a6b3e9be6862cc0825169a982'), ('lang', 'zh')]))

    mail.generate()
    print(mail.addr)
    print(mail.mailbox())
