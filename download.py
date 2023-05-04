import requests
import time
from bs4 import BeautifulSoup

from response import Response

def makeRespDict(url, resp):
    resp_dict = {}
    resp_dict['url'] = url
    resp_dict['status'] = resp.status_code
    resp_dict['response'] = resp.content
    
    return resp_dict
    
def download(url):
    resp = None
    try:
        resp = requests.get(url)
        if resp and resp.content:
            return Response(makeRespDict(url,resp))
    except (EOFError, ValueError) as e:
        pass
    except Exception as e:
        pass
    print(f"Spacetime Response error {resp} with url {url}.")
    return Response({
        "error": f"Spacetime Response error {resp} with url {url}.",
        "status": resp.status_code,
        "url": url})
