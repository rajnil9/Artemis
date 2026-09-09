"""
PhishX URL Feature Extraction Module.
Parses URL components, entropy, domain attributes, and suspicious patterns.
"""

# pyrefly: ignore [missing-import]
import tldextract
import re
import urllib.parse
import math

def extract_features(url):
    """
    Takes a raw URL string and extracts advanced lexical, structural, and heuristic features.
    These numerical features are what the RandomForest model actually analyzes.
    """
    url = str(url).strip()
    
    # Normalize by stripping protocol and www prefix for consistent lexical counting
    cleaned_url = url
    if cleaned_url.lower().startswith('http://'):
        cleaned_url = cleaned_url[7:]
    elif cleaned_url.lower().startswith('https://'):
        cleaned_url = cleaned_url[8:]
    if cleaned_url.lower().startswith('www.'):
        cleaned_url = cleaned_url[4:]
        
    features = {}
    features['length'] = len(cleaned_url)
    features['has_https'] = 1 if url.lower().startswith('https://') else 0
    
    # ---------------------------------------------------------
    # 1. STRUCTURAL CHARACTER COUNTS
    # ---------------------------------------------------------
    # Simple character counts that are abnormally high in malicious URLs.
    features['dot_count'] = cleaned_url.count('.')
    features['hyphen_count'] = cleaned_url.count('-')
    features['at_symbol'] = 1 if '@' in cleaned_url else 0
    features['slash_count'] = cleaned_url.count('/')
    
    # Calculate the ratio of digits to total length.
    features['digit_ratio'] = sum(c.isdigit() for c in cleaned_url) / max(len(cleaned_url), 1)
    
    # Count special characters commonly used in malicious query parameters or obfuscation.
    features['special_char_count'] = sum(cleaned_url.count(c) for c in ['=', '_', '?', '&', '%'])
    
    # ---------------------------------------------------------
    # 2. KEYWORD HEURISTICS (TYPOSQUATTING & SOCIAL ENGINEERING)
    # ---------------------------------------------------------
    url_lower = cleaned_url.lower()
    # Phishing attacks try to trick users by placing brand names or urgent words in the URL.
    generic_keywords = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'wallet']
    brand_keywords = [
        'paypal', 'apple', 'amazon', 'google', 'netflix', 
        'udemy', 'linkedin', 'facebook', 'microsoft', 'instagram', 
        'github', 'twitter', 'unstop', 'coursera', 'wikipedia', 
        'youtube', 'slack', 'zoom', 'spotify', 'adobe', 'stripe', 'devbyte'
    ]
    
    for kw in generic_keywords:
        features[f'has_{kw}'] = 1 if kw in url_lower else 0
        
    for kw in brand_keywords:
        features[f'has_{kw}'] = 0

    # ---------------------------------------------------------
    # 3. ADVANCED URL PARSING & NETWORK HEURISTICS
    # ---------------------------------------------------------
    # We wrap this in a try-except block because some malware datasets contain 
    # completely corrupted binary URLs that crash standard Python parsers.
    try:
        # urllib requires a protocol (http/https) to parse the domain vs path correctly.
        # We always prepend 'http://' to our cleaned_url to ensure standard parsing.
        parsed_url = 'http://' + cleaned_url
 
        # Parse the URL into components (scheme, netloc/domain, path, query params, etc.)
        parsed = urllib.parse.urlparse(parsed_url)
        # Use tldextract to accurately separate subdomains, root domain, and TLDs (like .co.uk).
        ext = tldextract.extract(parsed_url)
        
        domain = parsed.netloc.lower()

        # Check brand keywords against the extracted domain to detect typosquatting/brand abuse.
        features['is_legit_brand'] = 0
        for kw in brand_keywords:
            if kw in url_lower:
                # If the brand name appears in the URL, but the registered domain is NOT the brand's official domain
                if ext.domain.lower() != kw:
                    features[f'has_{kw}'] = 1
                else:
                    # It IS the official domain
                    features['is_legit_brand'] = 1

        # Check for open redirects or obfuscation tricks like 'http://safe.com//http://evil.com'
        features['double_slash'] = 1 if '//' in parsed.path else 0
        
        # Phishing links often have massive, complex query strings to pass tracking IDs or steal tokens.
        features['query_length'] = len(parsed.query)
        # Count the number of parameters (separated by '&') in the query string.
        features['parameter_count'] = parsed.query.count('&') + 1 if parsed.query else 0
        
        # Check if the domain is literally a raw IP address (e.g., 192.168.1.1) instead of a named domain.
        # This is a massive red flag for malware and phishing.
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        features['ip_based'] = 1 if ip_pattern.search(domain) else 0
        
        # Count subdomains. Malicious actors often use deeply nested subdomains 
        # (e.g., paypal.login.secure-auth.evil.com) to look legitimate.
        subdomains = ext.subdomain.split('.') if ext.subdomain else []
        subdomains = [sub for sub in subdomains if sub]
        features['subdomain_count'] = len(subdomains)
        
        # Check for clean root domain structure (e.g. domain.com without complex paths or query params)
        # Enforce zero subdomains for a true bare root domain
        features['is_root_domain'] = 1 if (not parsed.path or parsed.path == '/') and not parsed.query and features['subdomain_count'] == 0 else 0
        
        # Calculate brand entropy (Shannon entropy) on the domain name to detect DGA/obfuscated domains
        def shannon_entropy(s):
            if not s:
                return 0
            p, lns = [s.count(c) / len(s) for c in set(s)], len(s)
            return -sum(count * math.log2(count) for count in p)
        
        features['brand_entropy'] = shannon_entropy(ext.domain)
        
        # ---------------------------------------------------------
        # 4. THREAT INTELLIGENCE: SUSPICIOUS TLDs & SHORTENERS
        # ---------------------------------------------------------
        # Standard trusted TLDs vs high-risk abused TLDs
        standard_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'ca', 'app', 'dev', 'ai', 'in', 'design', 'tech', 'me', 'site', 'cloud', 'studio', 'online', 'store', 'space', 'agency', 'digital', 'money', 'sh', 'so', 'website', 'build', 'style'}
        features['is_standard_tld'] = 1 if ext.suffix in standard_tlds else 0
        
        trusted_platforms = {'github.io', 'now.sh', 'vercel.app', 'netlify.app', 'pages.dev', 'herokuapp.com', 'web.app', 'firebaseapp.com'}
        features['is_trusted_platform'] = 1 if f"{ext.domain}.{ext.suffix}" in trusted_platforms else 0
        
        suspicious_tlds = {'tk', 'xyz', 'top', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ru', 'buzz', 'info'}
        features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0
        
        # URL shorteners are heavily used in phishing SMS (smishing) and emails to hide the real destination.
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'goo.gl', 'buff.ly', 'ow.ly'}
        features['is_shortened'] = 1 if ext.domain + '.' + ext.suffix in shorteners else 0
        
        # ---------------------------------------------------------
        # 5. PATH-SPECIFIC DEFACEMENT HEURISTICS
        # ---------------------------------------------------------
        path = parsed.path.lower()
        features['path_length'] = len(path)
        
        executable_exts = ('.php', '.asp', '.aspx', '.cgi', '.jsp', '.html', '.htm')
        features['has_executable_ext'] = 1 if path.endswith(executable_exts) else 0
        
        features['path_depth'] = path.count('/')
        
        defacement_keywords = ['index', 'deface', 'hacked', 'admin', 'upload', 'images', 'wp-content', 'components', 'modules', 'includes', 'option', 'view']
        features['defacement_keywords'] = 1 if any(kw in path for kw in defacement_keywords) else 0
        
        features['hyphen_in_path_ratio'] = path.count('-') / max(len(path), 1)
        features['digit_in_path_ratio'] = sum(c.isdigit() for c in path) / max(len(path), 1)

    except Exception:
        # If the URL is so badly corrupted that it breaks the parser, we default these 
        # advanced features to 0 so the model can still use the basic character count features.
        features['is_legit_brand'] = 0
        features['is_root_domain'] = 0
        features['is_standard_tld'] = 0
        features['double_slash'] = 0
        features['query_length'] = 0
        features['parameter_count'] = 0
        features['ip_based'] = 0
        features['subdomain_count'] = 0
        features['suspicious_tld'] = 0
        features['is_shortened'] = 0
        features['path_length'] = 0
        features['has_executable_ext'] = 0
        features['path_depth'] = 0
        features['defacement_keywords'] = 0
        features['hyphen_in_path_ratio'] = 0.0
        features['digit_in_path_ratio'] = 0.0
        features['brand_entropy'] = 0.0
        
    return features