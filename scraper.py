import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import hashlib
from utils import get_logger

#alphanumeric regexes
ANregex = '^[a-z0-9]*$'
Splitregex = "[^0-9a-zA-Z]+"

#url processing
completed = []
hashedURLs = []
domains_hashed_pages = {}

#token data
#excuse this abomination
stopWords = ["a","about","above","after","again","against","all","am","an","and","any","are","aren't","as","at","be","because","been","before","being","below","between","both","but","by","can't","cannot","could","couldn't","did","didn't","do","does","doesn't","doing","don't","down","during","each","few","for","from","further","had","hadn't","has","hasn't","have","haven't","having","he","he'd","he'll","he's","her","here","here's","hers","herself","him","himself","his","how","how's","i","i'd","i'll","i'm","i've","if","in","into","is","isn't","it","it's","its","itself","let's","me","more","most","mustn't","my","myself","no","nor","not","of","off","on","once","only","or","other","ought","our","ours       ourselves","out","over","own","same","shan't","she","she'd","she'll","she's","should","shouldn't","so","some","such","than","that","that's","the","their","theirs","them","themselves","then","there","there's","these","they","they'd","they'll","they're","they've","this","those","through","to","too","under","until","up","very","was","wasn't","we","we'd","we'll","we're","we've","were","weren't","what","what's","when","when's","where","where's","which","while","who","who's","whom","why","why's","with","won't","would","wouldn't","you","you'd","you'll","you're","you've","your","yours","yourself","yourselves"]
tokenFrequencies = {}
longestPage = ("",-1)
subdomain_and_count = {}
logger = get_logger('CRAWLER')
total = 0


def getDomain(url):
    '''
    returns domain of url
    '''
    parsed_url = urlparse(url)
    return parsed_url.netloc

def getSubDomain(url):
    '''
    returns subdomain of url
    '''
    parsed_url = urlparse(url)
    return parsed_url.hostname.split('.')[0]
    
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
    '''
    coputes word frequencies from assignment 1
    '''
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
    '''
    compare hash to all hashes in domain and return if more than 80 percent similar
    '''
    for hashed_url in hashedURLs:
        common = 0
        for a,b in zip(hashed_url, simhashed):
            if a == b:
                common += 1
        similarity = common / len(simhashed)

        if similarity > .7:
            return True
    return False

def computeSimilarity(domain, subdomain, simhashed, url):
    '''
    iterate over visited domains and check if there is a similar page in that domain
    if domain doesnt exist, create domain if subdomain doesnt exist create it
    '''
    # for d in domains_hashed_pages.keys():
    #     if d == domain: 
    #         similar = compareHashes(domains_hashed_pages[domain], simhashed)
    #         if not similar:
    #             domains_hashed_pages[domain].append(simhashed)
                
    #         return similar
        
    for d in domains_hashed_pages.keys():
        if d == domain:
            for subd in domains_hashed_pages[d]:
                if subd == subdomain:
                    similar = compareHashes(domains_hashed_pages[domain][subdomain], simhashed)
                    if not similar:
                        domains_hashed_pages[domain][subdomain].append(simhashed)
                    return similar
    
    #domain or subdomain not found: add
    if domain in domains_hashed_pages:
        domains_hashed_pages[domain][subdomain] = [simhashed]
    else:
        domains_hashed_pages[domain] = {subdomain:[simhashed]}
        
    return False
        
    
def getLinksHTML(soup, url):
    '''
    first checks if page has links then if similar page has already been visited
    grabs all a tags and iterates through links if they are valid and not yet visited or repeats
    '''
    global total
    #stop if no links
    a_tags = soup.find_all('a')
    if len(a_tags) == 0:
        #logger.info('no tags found')
        return []
    
    simhashed = simhash(soup, url)
    subdomain = getSubDomain(url)
    #stop if this page is too similar
    if computeSimilarity(getDomain(url),subdomain,simhashed,url):
        #logger.info('too similar')
        return []
    
    #increments number of links in subdomain
    if (subdomain in subdomain_and_count):
        subdomain_and_count[subdomain] += 1
    else:
        subdomain_and_count[subdomain] = 1
        
    links = []
    for a_tag in a_tags:
        if not a_tag.get('href'):
            continue
        
        #craft absolute link and add to list to return if not visited and valid
        absolute_link = urljoin(url, defrag(a_tag.get('href')))
        if (absolute_link not in links and absolute_link not in completed) and is_valid(absolute_link):
            links.append(absolute_link)
            total += 1
            
        completed.append(absolute_link)
    #logger.info('size a tags: '+ str(len(a_tags)))  
    return links

def validHTTPStatus(resp):
    '''
    returns true only if status code is valid
    '''
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
    '''
    uses hashlib to create a 32 bit hash and returns a binary string representation
    '''
    token = token.encode('utf-8')
    h = hashlib.blake2b(token, digest_size=4)
    
    hash_bytes = h.digest()
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    binhash = bin(hash_int)[2:].zfill(32)
    
    return binhash

def saveTokenData(frequencies, totalWords, url):
    '''
    save token data to public variables and update stats for final report
    '''
    global tokenFrequencies
    global longestPage
    if longestPage[1] < totalWords:
        longestPage = (url, totalWords)
    
    #parse out stop words
    for stop in stopWords:
        if stop in frequencies:
            del frequencies[stop]
    
    #used for finding most common tokens
    for token, count in frequencies.items():
        if token in tokenFrequencies:
            tokenFrequencies[token] += count
        else:
            tokenFrequencies[token] = count

def simhash(soup, url):
    '''
    computes simhash of webpage given soup representation
    computes weights of tokens and hashes them to a 32 bit value
    adds or subtracts weights of each token to weight vector
    computes fingerprint from weight vector
    finally adds tokens and weights to list and sets to longest if applicable
    '''
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
    
    #saving token data
    totalWords = 0
    for token,freq in frequencies.items():
        totalWords += freq
        
    saveTokenData(frequencies, totalWords, url)
    
    return fingerprint

def extract_next_links(url, resp):
    #stop if page not valid
    if not validHTTPStatus(resp):
        #logger.info('not valid status')
        return []
    
    #stop if page too long
    if resp.size != None and int(resp.size) > 50000:
        #logger.info('too big or no size')
        return []
    
    soup = BeautifulSoup(resp.raw_response, "html.parser",from_encoding="iso-8859-1")
    
    #all valid unvisited links in this current page
    links = getLinksHTML(soup, url)

    #logger.info('returning links')
    return links

def is_valid(url):
    '''
    Ensures file extensions are readable and that we are crawling allowed domain
    '''
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
     
    pattern = r'^((.*\.ics\.uci\.edu\/?.*)|(.*\.cs\.uci\.edu\/?.*)|(.*\.informatics\.uci\.edu\/?.*)|(.*\.stat\.uci\.edu\/?.*))$'
    #pattern = r'^.*\.ics\.uci\.edu\/.*$'
    if not re.match(pattern, url.lower()):
        #logger.info('p1 error')
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            #logger.info('wrong scheme')
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|gctx|txt|py|java"
            + r"|png|tiff?|mid|mp2|mp3|mp4|bib|mpg|img|class"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|npy|sql|war|seq"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|bam"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1|bigwig"
            + r"|thmx|mso|arff|rtf|jar|csv|bw"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise