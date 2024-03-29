import requests
import cbor
import time
import pickle 

from utils.response import Response

def makeRespDict(url, resp, content):
    resp_dict = {}
    resp_dict['url'] = url
    resp_dict['status'] = resp.status_code
    
    if 'response' in content:
        depickled_repsonse = pickle.loads(content['response'])
        resp_dict['response'] = depickled_repsonse.content

    resp_dict['size'] = resp.headers.get('Content-Length')
    return resp_dict

def download(url, config, logger=None):
    host, port = config.cache_server
    resp = requests.get(
        f"http://{host}:{port}/",
        params=[("q", f"{url}"), ("u", f"{config.user_agent}")])
    try:
        if resp and resp.content:
            content = cbor.loads(resp.content)
            return Response(makeRespDict(content['url'], resp, content))
    except (EOFError, ValueError) as e:
        pass
    except Exception as e:
        pass
    logger.error(f"Spacetime Response error {resp} with url {url}.")
    return Response({
        "error": f"Spacetime Response error {resp} with url {url}.",
        "status": resp.status_code,
        "url": url})
