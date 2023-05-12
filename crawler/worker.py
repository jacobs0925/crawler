from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time
import scraper


class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            time.sleep(self.config.time_delay)
        with open('output.txt', 'a') as f:
            f.write('unique pages: ' + str(len(scraper.completed)) + '\n')
            f.write('longest page ' + scraper.longestPage[0] + ', ' + str(scraper.longestPage[1]) +'\n')
            f.write('most common tokens: \n')
            sorted_freqs = dict(sorted(scraper.tokenFrequencies.items(), key=lambda item: item[1], reverse=True))
            common_50 = list(sorted_freqs.items())[:50]
            
            for token, freq in common_50:
                f.write(token + ', ' + str(freq) + '\n')
            
            f.write('subdomains and pages: \n')
            for subdomain in scraper.domains_hashed_pages['ics.uci.edu']:
                f.write(subdomain + ', ' + str(scraper.subdomain_and_count[subdomain]) + '\n')
            f.write('all valid links scraped: ' + str(len(scraper.completed)) + '\n')