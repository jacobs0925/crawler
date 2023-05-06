import requests
import time
from bs4 import BeautifulSoup
from utils.response import Response
import cbor

def makeRespDict(url, resp):
    resp_dict = {}
    resp_dict['url'] = url
    resp_dict['status'] = resp.status_code
    resp_dict['response'] = resp.content
    resp_dict['size'] = resp.headers.get('Content-Length')
    return resp_dict

def download(url, config, logger=None):
    host, port = config.cache_server
    resp = requests.get(
        f"http://{host}:{port}/",
        params=[("q", f"{url}"), ("u", f"{config.user_agent}")])
    try:
        if resp and resp.content:
            return Response(makeRespDict(url,resp))
    except (EOFError, ValueError, Exception) as e:
        pass
    logger.error(f"Spacetime Response error {resp} with url {url}.")
    return Response({
        "error": f"Spacetime Response error {resp} with url {url}.",
        "status": resp.status_code,
        "url": url})
