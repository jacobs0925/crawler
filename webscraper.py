import re
from download import download
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import hashlib

completed = []
ANregex = '^[a-z0-9]*$'
Splitregex = "[^0-9a-zA-Z]+"
domains_hashed_pages = {}
hashedURLs = []

def getDomain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc
    
def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def defrag(url):
    '''
    defragment url
    '''
    if '#' in url:
        return url.split('#')[0]
    else:
        return url

def computeWordFrequencies(text):
    tokens = {}
    for word in re.split(Splitregex, text):
        word = word.strip()
        if word == "":
            continue
        match = re.match(ANregex, word,re.IGNORECASE)
        if match == None:
            continue
        else:
            word  = match.group()
        if word.lower() not in tokens:
            tokens[word.lower()] = 1
        else:
            tokens[word.lower()] = tokens[word.lower()]+1
    return tokens

def compareHashes(hashedURLs, simhashed):
    for hashed_url in hashedURLs:
        common = 0
        for a,b in zip(hashed_url, simhashed):
            if a == b:
                common += 1
        similarity = common / len(simhashed)

        if similarity > .8:
            return True
    return False

def computeSimilarity(domain, simhashed):
    '''
    iterate over visited domains and check if there is a similar page in that domain
    if domain doesnt exist, create domain
    '''
    for d in domains_hashed_pages.keys():
        if d == domain: 
            similar = compareHashes(domains_hashed_pages[domain], simhashed)
            if not similar:
                domains_hashed_pages[domain].append(simhashed)
                
            return similar
    
    #domain not found add domain
    domains_hashed_pages[domain] = [simhashed]
    return False
        
    
def getLinksHTML(soup, url):
    '''
    first checks if page has links then if similar page has already been visited
    grabs all a tags and iterates through links if they are valid and not yet visited or repeats
    '''
    #stop if no links
    a_tags = soup.find_all('a')
    if len(a_tags) == 0:
        return []
    
    simhashed = simhash(soup)
    #stop if this page is too similar
    if computeSimilarity(getDomain(url), simhashed):
        return []
    
    links = []
    for a_tag in a_tags:
        if not a_tag.get('href'):
            continue
        
        #craft absolute link and add to list to return if not visited and valid
        absolute_link = urljoin(url, defrag(a_tag.get('href')))
        if (absolute_link not in links and absolute_link not in completed) and is_valid(absolute_link):
            completed.append(absolute_link)
            links.append(absolute_link)
            
    return links

def validHTTPStatus(resp):
    status = resp.status
    if 200 <= status < 300:
        #successful
        if status == 204:
            #No content
            return False
        else:
            return True
    elif 300 <= status < 400:
        #max 30 redirects, requests library handles following redirects
        return True
    else:
        return False

def hashToken(token):
    token = token.encode('utf-8')
    h = hashlib.blake2b(token, digest_size=4)
    
    hash_bytes = h.digest()
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    binhash = bin(hash_int)[2:].zfill(32)
    
    return binhash

def simhash(soup):
    text = soup.text
    text = text.replace('\n','')
    frequencies = computeWordFrequencies(text)
    hashed_tokens = {key:hashToken(key) for key in frequencies.keys()}
    
    #32 bit weight vector
    V = [0] * 32
    #for each word
    for token,hash in hashed_tokens.items():
        #for each bit in hash
        for i in range(len(hash)):
            if hash[i] == '0':
                V[i] -= frequencies[token]
            elif hash[i] == '1':
                V[i] += frequencies[token]
    
    #32 bit fingerprint
    fingerprint = ''.join(['1' if bit > 0 else '0' for bit in V])
    
    return fingerprint

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    
    #stop if page not valid
    if not validHTTPStatus(resp):
        return []
    
    #CHANGE THIS TO RAW_RESPONSE.CONTENT BEFORE GOING LIVE
    soup = BeautifulSoup(resp.raw_response, "html.parser")
    
    #all valid unvisited links in this current page
    #CHANGE THIS TO RAW_RESPONSE.URL
    links = getLinksHTML(soup, url)
    
    #soup.text for all visible text

    return links

def is_valid(url):
    '''
    Ensures file extensions are readable and that we are crawling allowed domain
    '''
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    
    pattern = r'^((.*\.ics\.uci\.edu\/.*)|(.*\.cs\.uci\.edu\/.*)|(.*\.informatics\.uci\.edu\/.*)|(.*\.stat\.uci\.edu\/.*))$'
    if not re.match(pattern, url.lower()):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
#,'https://www.ics.uci.edu/','https://www.stat.uci.edu/','https://www.informatics.uci.edu/','https://www.cs.uci.edu/'
if __name__ == '__main__':
    j = 1
    seeds = ['https://www.ics.uci.edu/','https://www.stat.uci.edu/','https://www.informatics.uci.edu/','https://www.cs.uci.edu/']
    completed.extend(seeds)
    #seeds = ['https://swiki.ics.uci.edu/doku.php/start?rev=1609807694','https://swiki.ics.uci.edu/doku.php/start?rev=1617220282']
    while (len(seeds) > 0):
        top = seeds.pop(0)
        print(j, 'current link',top)
        resp = download(top)
        seeds.extend(extract_next_links(top, resp))
        time.sleep(.5)
        j += 1
    print('links',len(completed))