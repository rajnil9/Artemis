"""
Artemis Email Feature Extraction Module.
Extracts email header, body, URL counts, and domain features.
"""

import pandas as pd
import re
import unicodedata
from sklearn.base import BaseEstimator, TransformerMixin

HOMOGLYPH_MAP = {
    # Cyrillic lowercase lookalikes
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0432': 'b', '\u043d': 'h',
    '\u0442': 't', '\u043c': 'm', '\u043a': 'k', '\u045e': 'u',
    # Cyrillic uppercase lookalikes
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u0406': 'I', '\u0408': 'J', '\u041a': 'K',
    '\u041c': 'M', '\u041e': 'O', '\u0420': 'P', '\u0422': 'T',
    '\u0425': 'X', '\u0423': 'Y',
    # Greek lowercase & uppercase lookalikes
    '\u03b1': 'a', '\u03b2': 'b', '\u03b5': 'e', '\u03bf': 'o',
    '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'u', '\u03bd': 'v',
    '\u03ba': 'k', '\u03b9': 'i',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u039f': 'O',
    '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X',
}

def sanitize_adversarial_text(text: str) -> tuple[str, dict]:
    if not isinstance(text, str):
        return text, {
            "evasion_detected": False, 
            "zero_width_chars_removed": 0, 
            "homoglyphs_normalized": False,
            "homoglyphs_count": 0
        }
        
    # 0. Decode any literal Unicode escape sequences (e.g. u{200B}, \u200B, u{0430}, \u0430)
    # This ensures command lines without shell escape support are seamlessly parsed.
    try:
        text = re.sub(r'(?i)(?:\\u|(?<=[a-zA-Z0-9\s])u|(?<=^)u)\{([0-9a-fA-F]{4,6})\}', lambda m: chr(int(m.group(1), 16)), text)
        text = re.sub(r'(?i)\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    except Exception:
        pass

    # 1. Strip zero-width, invisible, and bidirectional override characters
    zw_pattern = re.compile(r'[\u200B-\u200F\uFEFF\u00AD\u2060-\u2069\u180E\u202A-\u202E]')
    zw_matches = zw_pattern.findall(text)
    zero_width_removed = len(zw_matches)
    text_clean = zw_pattern.sub('', text)
    
    # 2. Normalize deceptive homoglyphs (Cyrillic, Greek, lookalikes)
    homoglyphs_count = sum(1 for c in text_clean if c in HOMOGLYPH_MAP)
    replaced_text = ''.join(HOMOGLYPH_MAP.get(c, c) for c in text_clean)
    
    # 3. Apply NFKD normalization for full-width characters and ligatures
    normalized_text = unicodedata.normalize('NFKD', replaced_text)
    homoglyphs_normalized = homoglyphs_count > 0 or (normalized_text != text_clean)
    
    evasion_detected = zero_width_removed > 0 or homoglyphs_normalized
    
    telemetry = {
        "evasion_detected": evasion_detected,
        "zero_width_chars_removed": zero_width_removed,
        "homoglyphs_normalized": homoglyphs_normalized,
        "homoglyphs_count": homoglyphs_count
    }
    
    return normalized_text, telemetry

class MetadataExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # X is expected to be a DataFrame with 'subject' and 'body'
        df = pd.DataFrame(index=X.index)
        
        # Sanitize adversarial text
        sanitized_subject = X['subject'].astype(str).fillna('').apply(lambda t: sanitize_adversarial_text(t)[0])
        sanitized_body = X['body'].astype(str).fillna('').apply(lambda t: sanitize_adversarial_text(t)[0])
        
        # Combine text for overall metrics
        text_series = sanitized_subject + " " + sanitized_body
        
        # 1. Length metrics
        char_count = text_series.str.len().replace(0, 1) # avoid division by zero
        word_count = text_series.str.split().str.len().replace(0, 1)
        
        # 2. URL ratio (per word)
        url_count = text_series.str.count(r'http[s]?://|www\.')
        df['url_ratio'] = url_count / word_count
        
        # 3. Uppercase ratio (per char)
        upper_counts = text_series.str.count(r'[A-Z]')
        df['uppercase_ratio'] = upper_counts / char_count
        
        # 4. Special Characters typically abused in spam (per char)
        exclamation_count = text_series.str.count('!')
        df['exclamation_ratio'] = exclamation_count / char_count
        
        dollar_count = text_series.str.count(r'\$')
        df['dollar_ratio'] = dollar_count / char_count
        
        # 5. Threat/Urgent keywords (Phishing)
        lower_text = text_series.str.lower()
        
        urgent_words = [
            'urgent', 'compromised', 'verify', 'secure', 'suspended', 
            'alert', 'password', 'reset', 'billing', 'unauthorized', 
            'locked', 'immediately', 'action', 'security', 'notification',
            'wire', 'gift card', 'payroll', 'routing number', 'chancellor'
        ]
        urgent_count = pd.Series(0.0, index=text_series.index)
        for word in urgent_words:
            urgent_count += lower_text.str.count(rf'\b{word}\b')
        df['urgent_ratio'] = urgent_count / word_count
            
        scam_words = [
            'bitcoin', 'wallet', 'invoice', 'payment', 'bank', 
            'account', 'transfer', 'dollars', 'fund', 'claim', 
            'winnings', 'money', 'inherit', 'lottery', 'winner', 'gift'
        ]
        scam_count = pd.Series(0.0, index=text_series.index)
        for word in scam_words:
            scam_count += lower_text.str.count(rf'\b{word}\b')
        df['scam_ratio'] = scam_count / word_count
        
        # 6. Commercial Keywords (Spam)
        spam_words = [
            'unsubscribe', 'opt-out', 'manage preferences', 'discount', 
            'clearance', 'guarantee', 'promo'
        ]
        spam_count = pd.Series(0.0, index=text_series.index)
        for word in spam_words:
            spam_count += lower_text.str.count(rf'\b{word}\b')
        df['spam_ratio'] = spam_count / word_count
        
        # 7. LLM Corporate Writing Tone (Phishing/Spam)
        corporate_words = [
            'kindly', 'please ensure', 'promptly', 'appreciate', 
            'assist', 'regards', 'cordially', 'i hope this'
        ]
        corporate_count = pd.Series(0.0, index=text_series.index)
        for word in corporate_words:
            corporate_count += lower_text.str.count(rf'\b{word}\b')
        df['llm_corporate_ratio'] = corporate_count / word_count
        
        # Ensure all columns are float64 to play nicely with StandardScaler
        return df.astype(float)

    def get_feature_names_out(self, input_features=None):
        import numpy as np
        return np.array([
            'url_ratio', 'uppercase_ratio', 'exclamation_ratio', 
            'dollar_ratio', 'urgent_ratio', 'scam_ratio', 
            'spam_ratio', 'llm_corporate_ratio'
        ])

def extract_email_metadata(df):
    extractor = MetadataExtractor()
    return extractor.transform(df)