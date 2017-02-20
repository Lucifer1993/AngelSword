import requests

headers = dict()

with open("packet.txt") as f:
    for line in f.readlines():
        line = line.strip()
        if line.find("HTTP/1.1") is not -1:
            continue
        headers[line.split(":")[0]]=line.split(":")[1]
url = "http://"+headers["Host"].strip() + "/"
print(url)
req = requests.get(url, headers=headers, timeout=6, verify=False)
print(req.text)
        