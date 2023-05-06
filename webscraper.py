import re
from download import download
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import hashlib

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
    #stop if no links
    a_tags = soup.find_all('a')
    if len(a_tags) == 0:
        return []
    
    simhashed = simhash(soup, url)
    subdomain = getSubDomain(url)
    #stop if this page is too similar
    if computeSimilarity(getDomain(url),subdomain,simhashed,url):
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
            
            flag = True
            filters = ['?','.gctx','.txt','.py','.java','.class','.pdf','.npy','.sql','.war','.seq','.bed','.bam','.bigwig','.bw']
            for f in filters:
                if f in absolute_link:
                    flag = False
                    
            if flag:
                links.append(absolute_link)
        completed.append(absolute_link)
            
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
        return []
    
    #stop if page too long
    if resp.size != None and int(resp.size) > 50000:
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
    #pattern = r'^.*\.ics\.uci\.edu\/.*$'
    if not re.match(pattern, url.lower()):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4|bib|mpg|img"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

if __name__ == '__main__':
    j = 1
    
    
    seeds = ['https://www.ics.uci.edu/','https://www.stat.uci.edu/','https://www.informatics.uci.edu/','https://www.cs.uci.edu/']
    #seeds = ['https://www.ics.uci.edu/','https://www.stat.uci.edu/','https://www.informatics.uci.edu/','https://www.cs.uci.edu/','https://grape.ics.uci.edu/wiki/public/zip-attachment/wiki/cs122b-2018-winter-project1-eclipse-project/']
    completed.extend(seeds)
    while (len(seeds) > 0):
        top = seeds.pop(0)
        print(j, 'current link',top)
        with open('output.txt', 'a') as f:
            f.write(str(j) +  ' ' + top + '\n')
        resp = download(top)
        if resp:
            seeds.extend(extract_next_links(top, resp))
            time.sleep(.5)
            j += 1
            
    with open('output.txt', 'a') as f:
        f.write('unique pages: ' + str(len(completed)) + '\n')
        f.write('longest page ' + longestPage[0] + ', ' + str(longestPage[1]) +'\n')
        f.write('most common tokens: \n')
        sorted_freqs = dict(sorted(tokenFrequencies.items(), key=lambda item: item[1], reverse=True))
        common_50 = list(sorted_freqs.items())[:50]
        
        for token, freq in common_50:
            f.write(token + ', ' + str(freq) + '\n')
        
        f.write('subdomains and pages: \n')
        for subdomain in domains_hashed_pages['www.ics.uci.edu']:
            f.write(subdomain + ', ' + str(subdomain_and_count[subdomain]) + '\n')
        
    print('links',len(completed))