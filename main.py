import tldextract
import Levenshtein as lv 

legitimate_domains = ['cisco.com','crowdstrike.com','nist.gov']

test_urls = [

    'https://www.nist.gov/new-events',
    'htpps://www.cisco.com',
    'https://www.crowdstrike.com',
    'htpps://www.cisc0.c0m'
    'https://www.cr0wdstrik3.com',
    'http://www.cisc0.net',
    'https://www.nist.net'

]

def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix


def is_misspelled_domain(domain, legitimate_domains, threshold= 0.9):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain, legit_domain)
        if similarity >= threshold:
            return False # Which the domain is correct and not misspelled 
        return True # Not close match found, probably is misspelled 
    
def has_suspicious_subdomain(subdomain, legitmant_domains):
    if not subdomain:
        return False # no subdomain, nothing to check
    
    for legit_domain in legitimate_domains:
        legit_domain = legit_domain.split('.')[0]
        if legit_name in subdomain.lower():
            return True
    return False
        
    
def is_phishing_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    # Check if it's a known legitimate domain
    if f"{domain}.{suffix}" in legitimate_domains:
        return False
    
    # Check for misspelled domain names
    if is_misspelled_domain(domain, legitimate_domains):
        print(f'Potenial phishing detected: {url}')
        return True
    
    # Check for suspicious subdomains
    if has_suspicious_subdomain(subdomain, legitimate_domains):
        print(f'Potenial phishing(suspicious subdomain): {url}')
        return True
    
    return False
    







