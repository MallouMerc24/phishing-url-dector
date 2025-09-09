# phishing-url-dector
A Python tool for detecting potential phishing URLs using domain extraction, Levenshtein similarity, and subdomain analysis.

Extracting the domain – separating the subdomain, main domain, and suffix (e.g., .com, .net).

Detecting misspellings – comparing the domain against known safe domains using Levenshtein similarity to find lookalike domains.

Flagging suspicious subdomains – catching URLs that try to trick users with fake subdomains (e.g., login.crowdstrike.support.com).

The script prints alerts when it detects a potentially malicious URL. It can be expanded by adding more legitimate domains or adjusting similarity thresholds.
