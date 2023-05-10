import pickle
class Response(object):
    def __init__(self, resp_dict):
        self.url = resp_dict["url"]
        self.status = resp_dict["status"]
        self.error = resp_dict["error"] if "error" in resp_dict else None
        self.size = resp_dict['size'] if 'size' in resp_dict else 0
        try:
            self.raw_response = (
                resp_dict["response"]
                if "response" in resp_dict else
                None)
        except TypeError:
            self.raw_response = None
