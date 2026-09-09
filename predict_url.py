"""
Artemis URL Phishing & Safety Prediction Engine.
Evaluates URL safety score using Artemis trained model artifact.
"""

import argparse
# pyrefly: ignore [missing-import]
import joblib
import json
import os
import re
import urllib.parse
import numpy as np
import pandas as pd
from url_features import extract_features

def generate_analysis_summary(prediction, features):
    headlines = {
        "benign": "Classified as Benign (Safe)",
        "phishing": "High Risk: Phishing Alert",
        "malware": "Critical Risk: Malware Host",
        "defacement": "Warning: Defaced Webpage"
    }
    explanations = {
        "benign": "The URL exhibits standard domain parameters with clean lexical features and no indicators of typosquatting or path manipulation.",
        "phishing": "This URL exhibits deceptive characteristics commonly used to steal credentials or masquerade as trusted brands.",
        "malware": "This URL demonstrates structural anomalies frequently associated with hosting or distributing malicious payloads.",
        "defacement": "This URL contains path-level signatures suggesting a compromised or defaced legitimate domain."
    }
    
    headline = headlines.get(prediction, "Unknown Classification")
    explanation = explanations.get(prediction, "No explanation available.")
    
    factors = []
    if features.get('is_institutional') == 1:
        factors.append("Verified accredited educational or governmental institution (.ac.*, .edu, .gov).")
    if features.get('is_cms_path') == 1:
        factors.append("URL contains standard Content Management System (CMS) directories.")
    if features.get('deep_payload_drop') == 1:
        factors.append("URL hosts a binary payload deeply nested within a directory structure.")
    if features.get('has_malware_keyword') == 1:
        factors.append("Contains lexical keywords associated with malware delivery or C2 infrastructure.")
    if features.get('is_legit_brand') == 1:
        factors.append("Verified as official brand domain.")
    if features.get('brand_impersonation_score') == 1 or features.get('min_brand_edit_distance', 99) <= 2:
        factors.append("Domain closely resembles a high-value brand (Typosquatting/Impersonation).")
    if features.get('has_homoglyphs') == 1:
        factors.append("Contains deceptive character substitutions (Homoglyphs).")
    if features.get('suspicious_tld') == 1:
        factors.append("Uses a high-risk or commonly abused Top-Level Domain (TLD).")
    if features.get('ip_based') == 1:
        factors.append("Uses a raw IP address instead of a registered domain.")
    if features.get('has_binary_payload_ext') == 1:
        factors.append("Path ends with a binary or script-dropping executable extension.")
    if features.get('has_dynamic_script_ext') == 1:
        factors.append("Path ends with a dynamic web script extension.")
    if features.get('defacement_keywords') == 1:
        factors.append("Path contains keywords frequently found in defaced sites.")
    if features.get('is_shortened') == 1:
        factors.append("URL uses a known link shortening service to obfuscate the destination.")
    if features.get('double_slash') == 1:
        factors.append("Contains double slashes indicative of open redirect abuse.")
    if features.get('path_depth', 0) > 3:
        factors.append(f"Deeply nested URL path structure (Depth: {features.get('path_depth')}).")
    if features.get('subdomain_count', 0) > 2:
        factors.append(f"High number of nested subdomains (Count: {features.get('subdomain_count')}).")
        
    if len(factors) < 3:
        if features.get('length', 0) > 75:
            factors.append("URL is abnormally long, often used to hide suspicious parameters.")
        if features.get('digit_ratio', 0) > 0.2:
            factors.append("High ratio of numeric digits, indicating potential machine-generated strings.")
            
    if not factors:
        if prediction == "benign":
            factors = [
                "Valid registered root domain without brand impersonation triggers",
                "Standard path depth and character length ratios",
                "No suspicious Top-Level Domain (TLD) or raw IP hosting"
            ]
        else:
            factors.append("Lexical structure aligns with typical web standards.")
        
    return {
        "headline": headline,
        "explanation": explanation,
        "key_factors": factors[:3]
    }

def predict_url(url: str) -> dict:
    model_path = os.path.join(os.path.dirname(__file__), 'models', 'artemis_url_model.pkl')
    if not os.path.exists(model_path):
        return {"error": f"Model not found at {model_path}. Please run train_url.py first."}
        
    artifact = joblib.load(model_path)
    if isinstance(artifact, dict) and 'model' in artifact and 'label_encoder' in artifact:
        model = artifact['model']
        le = artifact['label_encoder']
        feature_names = artifact.get('feature_names', None)
    else:
        model = artifact
        le = None
        feature_names = None
    
    features = extract_features(url)
    expected_features = feature_names if feature_names else (model.feature_name_ if hasattr(model, 'feature_name_') else None)
    if expected_features:
        features = {col: features.get(col, 0) for col in expected_features}
    X = pd.DataFrame([features])
    
    raw_prediction = model.predict(X)[0]
    
    if le:
        prediction = str(le.inverse_transform([raw_prediction])[0])
        class_names = le.classes_
    else:
        prediction = str(raw_prediction)
        class_names = model.classes_
    
    probabilities = model.predict_proba(X)[0]
    
    try:
        raw_logits = model.predict(X, raw_score=True)[0]
    except Exception:
        raw_logits = np.zeros(len(class_names))
        
    exponentials = np.exp(raw_logits)
    denominator = np.sum(exponentials)
    
    raw_logits_dict = {}
    exponentials_dict = {}
    class_probabilities = {}
    
    for cls, logit, exp, prob in zip(class_names, raw_logits, exponentials, probabilities):
        perc = float(round(prob * 100, 2))
        cls_str = str(cls)
        class_probabilities[cls_str] = perc
        raw_logits_dict[cls_str] = float(round(logit, 3))
        exponentials_dict[cls_str] = float(round(exp, 3))
        
    logits_str = ", ".join([f"{k}={v}" for k, v in raw_logits_dict.items()])
    exp_str = ", ".join([f"{k}={v}" for k, v in exponentials_dict.items()])
    
    top_class = prediction
    top_class_exp = exponentials_dict.get(top_class, 0.0)
    top_class_perc = class_probabilities.get(top_class, 0.0)
    
    mathematical_breakdown = {
        "formula": "P(k) = e^(z_k) / Sum(e^(z_j))",
        "raw_logits_z": raw_logits_dict,
        "exponentials_exp_z": exponentials_dict,
        "sum_denominator": float(round(denominator, 3)),
        "step_by_step": [
            f"Step 1: Gathered raw tree margin scores (logits) from LightGBM ensemble trees: {logits_str}",
            f"Step 2: Applied exponential transformation e^(z_k) to eliminate negative values: {exp_str}",
            f"Step 3: Summed exponentials (Denominator = {round(denominator, 3)}). Divided each by total sum to normalize probabilities (e.g., {top_class} = {top_class_exp} / {round(denominator, 3)} = {top_class_perc}%)."
        ]
    }
    
    # Parse hostname for institutional TLD checks (.edu, .ac.*, .gov, .mil, and verified state portals)
    parsed_netloc = urllib.parse.urlparse(url if "://" in url else "http://" + url).netloc.lower().split(':')[0]
    institutional_domains = {'makaut.net', 'makautexam.net', 'makautwb.ac.in'}
    is_institutional = (
        bool(re.search(r'\.(edu|gov|mil)(\.[a-z]{2,4})?$|\.ac\.[a-z]{2,4}$', parsed_netloc))
        or any(parsed_netloc == d or parsed_netloc.endswith('.' + d) for d in institutional_domains)
    )
    if is_institutional:
        features['is_institutional'] = 1
        
    # OVERRIDE 1: Security Whitelist (Protects Legit Brands like github.com)
    if features.get('is_legit_brand') == 1:
        original_pred = prediction
        prediction = "benign"
        for cls in class_probabilities:
            class_probabilities[cls] = 100.0 if cls == "benign" else 0.0
        mathematical_breakdown["step_by_step"].append(
            f"Step 4: Security Whitelist Override - Originally predicted '{original_pred}', but the domain is a verified safe brand. Overridden to benign=100.0%."
        )
        
    # OVERRIDE 1B: Academic & Government Institutional Safeguard
    elif is_institutional and prediction == "phishing" and features.get('has_binary_payload_ext', 0) == 0:
        original_pred = prediction
        prediction = "benign"
        for cls in class_probabilities:
            class_probabilities[cls] = 100.0 if cls == "benign" else 0.0
        mathematical_breakdown["step_by_step"].append(
            f"Step 4: Institutional Safeguard Override - Originally predicted '{original_pred}', but the domain is a verified accredited Academic or Government institution ({parsed_netloc}). Overridden to benign=100.0%."
        )
        
    # OVERRIDE 2: Fix Defacement confused as Benign or Phishing
    elif prediction in ["benign", "phishing"] and features.get('is_cms_path') == 1 and features.get('defacement_keywords') == 1:
        prediction = "defacement"
        mathematical_breakdown["step_by_step"].append(
            "Step 4: Tie-Breaker - Prediction overridden to Defacement due to high-confidence CMS defacement path indicators."
        )
         
    # OVERRIDE 3: Fix Malware confused as Phishing
    elif prediction == "phishing" and features.get('has_binary_payload_ext') == 1 and features.get('brand_impersonation_score', 0) == 0:
        prediction = "malware"
        mathematical_breakdown["step_by_step"].append(
            "Step 4: Tie-Breaker - Phishing prediction overridden to Malware due to executable payload drop without brand impersonation."
        )
    
    analysis_summary = generate_analysis_summary(prediction, features)
    
    response = {
        "status": prediction,
        "class_probabilities": class_probabilities,
        "analysis_summary": analysis_summary,
        "mathematical_breakdown": mathematical_breakdown,
        "extracted_features": features
    }
    
    return response

def main():
    parser = argparse.ArgumentParser(description="Predict if a URL is phishing or safe.")
    parser.add_argument("url", type=str, help="The URL to check")
    args = parser.parse_args()
    
    response = predict_url(args.url)
    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    main()