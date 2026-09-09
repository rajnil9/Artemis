"""
Email Prediction Engine.
Processes email header/body features and outputs calibrated 3-class classification scores.
"""

import argparse
import joblib
import json
import os
import pandas as pd
from email_features import MetadataExtractor, sanitize_adversarial_text

try:
    from urlextract import URLExtract
except ImportError:
    import sys
    print(json.dumps({"error": "urlextract library not found. Please run 'pip install urlextract'."}))
    sys.exit(1)

try:
    from predict_url import predict_url
except ImportError:
    predict_url = None

def scan_semantic_threats(subject, body):
    """
    Enterprise Behavioral Threat & Semantic Intent Arbiter.
    Detects AI-generated (LLM) polymorphic attacks:
    - Business Email Compromise (BEC) / Wire Fraud
    - Credential Phishing
    - High-Pressure Financial / Pharma / Work-from-Home Spam
    """
    import re
    full_text = f"{subject}\n{body}".lower()
    
    # 1. Business Email Compromise (BEC) / Wire Fraud / Credential Theft
    bec_rules = [
        (r'\b(bank(ing)? partner|bank account|remit(tance)?|wire|ach|routing|treasury)\b.*(changed|new|updat|consolidat|direct|differ)',
         "Detected BEC / Wire Fraud: Request to divert electronic funds/remittance to a different account.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'(do not|don\'t) remit payment to (our )?(previously|old|former)',
         "High-Risk Payment Interception: Explicit instruction to bypass existing authorized banking records.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'\bwire transfers? must be directed',
         "Mandated Wire Redirection: Enforced instruction directing wire transfers to external accounts.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'new(ly)? assigned (bank )?account',
         "Unverified Financial Update: Introduction of unverified bank account details for upcoming payments.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'(gift card|itunes card|google play card).*(urgent|purchase|send|buy)',
         "Gift Card Extortion: Urgent demand to purchase and transmit retail gift cards.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'(direct deposit|payroll).*(change|update|new bank)',
         "Payroll Diversion: Unauthorized request to alter direct deposit instructions.", "T1566.001", "Phishing: Spearphishing Attachment/Link", "Critical"),
        (r'(password|account|access|inbox).*(suspend|terminat|lock|expir).*(24 hours|immediately|urgent|today)',
         "Urgent Credential Threat: Coercive deadline threatening immediate account suspension.", "T1566.002", "Phishing: Spearphishing Link", "Critical"),
        (r'(click here|verify your identity|confirm credentials).*(http[s]?://|bit\.ly|tinyurl)',
         "Credential Harvesting: Suspicious link prompting user to confirm or verify credentials.", "T1566.002", "Phishing: Spearphishing Link", "Critical"),
        (r'\b(unusual login|login from a new location|document shared with you|mailbox (storage )?almost full|tax document|invoice available for review|verify your account|password will expire|payment failed)\b',
         "Credential Harvesting / Phishing Hook: High-risk template mimicking automated IT or Financial alerts.", "T1566.002", "Phishing: Spearphishing Link", "Critical")
    ]
    
    # 2. Commercial / Unsolicited Marketing / Get-Rich / Pharma Spam
    spam_rules = [
        (r'\b(viagra|cialis|cheap meds|medications online|without prescription|no prescription|buy prescription)\b',
         "Pharmaceutical Spam: Unsolicited promotion of prescription medications without medical oversight.", "T1598", "Phishing for Information", "Low / Informational"),
        (r'\b(earn \$\d+|make (more )?money|from (my|your) laptop|no experience.*no investment|no boss|work from home)\b',
         "Work-From-Home Spam: High-risk get-rich solicitation promising unrealistic income with no experience.", "T1598", "Phishing for Information", "Low / Informational"),
        (r'\b(penny stock|small-cap stock|stock pick|could 10x|\+\d+%\s*in\s*\d+\s*days)\b',
         "Speculative Financial Spam: Unsolicited micro-cap stock promotion / pump-and-dump signals.", "T1598", "Phishing for Information", "Low / Informational"),
        (r'\b(order today.*bonus|guaranteed lowest prices|discreetly|confidential packaging)\b',
         "Aggressive Commercial Spam: High-pressure marketing solicitation with unsolicited bonuses.", "T1598", "Phishing for Information", "Low / Informational"),
        (r'\b(flash sale|special promotion|exclusive offer|lowest prices|reward(s)?|free gift card|bonus|save up to|discount|upgrade|premium features|introductory price|loyalty points|weekend deals|savings)\b',
         "Bulk Promotional Spam: Mass marketing terminology and unsolicited discount offers.", "T1598", "Phishing for Information", "Low / Informational")
    ]
    
    bec_hits = [rule for rule in bec_rules if re.search(rule[0], full_text)]
    spam_hits = [rule for rule in spam_rules if re.search(rule[0], full_text)]
    
    return bec_hits, spam_hits

def generate_analysis_summary(prediction, subject, body, threat_factors=None, adversarial_defense=None, url_results=None):
    headlines = {
        "safe": "Classified as Safe",
        "phishing": "High Risk: Phishing / BEC Alert",
        "spam": "Warning: Spam Detected"
    }
    explanations = {
        "safe": "The email exhibits characteristics of normal conversational or transactional communication with no malicious payload.",
        "phishing": "The email contains indicators of social engineering, credential harvesting, financial redirection, or deceptive intent.",
        "spam": "The email contains bulk commercial marketing, financial hype, or unsolicited promotional content."
    }
    
    # Check for multi-vector threat
    has_malicious_url = any(u.get('status') in ['phishing', 'malware', 'defacement'] for u in (url_results or []))
    if prediction == "phishing" and has_malicious_url:
        headline = "High Risk: Multi-Vector Phishing Attack (Deceptive Text + Hostile URL)"
        explanation = "The email pairs coercive social engineering messaging with confirmed malicious/phishing links to execute an attack."
    else:
        headline = headlines.get(prediction, "Unknown Classification")
        explanation = explanations.get(prediction, "No explanation available.")
    
    text_factors = [tf[1] if isinstance(tf, tuple) else tf for tf in threat_factors] if threat_factors else []
    
    # Re-extract statistical features
    extractor = MetadataExtractor()
    df_input = pd.DataFrame({'subject': [subject], 'body': [body]})
    features_df = extractor.transform(df_input)
    
    url_ratio = features_df['url_ratio'].iloc[0]
    uppercase_ratio = features_df['uppercase_ratio'].iloc[0]
    exclamation_ratio = features_df['exclamation_ratio'].iloc[0]
    dollar_ratio = features_df['dollar_ratio'].iloc[0]
    urgent_ratio = features_df['urgent_ratio'].iloc[0]
    spam_ratio = features_df['spam_ratio'].iloc[0]
    
    if url_ratio > 0.05:
        text_factors.append(f"High density of embedded links (URL Ratio: {url_ratio:.2f}).")
    if uppercase_ratio > 0.1:
        text_factors.append(f"Abnormal volume of capitalized letters (Ratio: {uppercase_ratio:.2f}).")
    if exclamation_ratio > 0.02:
        text_factors.append("High usage of exclamation marks indicating urgency or pressure.")
    if dollar_ratio > 0.01:
        text_factors.append("References financial transactions, payments, or currency.")
    if urgent_ratio > 0:
        text_factors.append("Detected high-risk social engineering or urgent keywords.")
    if spam_ratio > 0:
        text_factors.append("Detected bulk commercial or promotional marketing keywords.")
        
    if not text_factors:
        if prediction == "safe":
            text_factors = [
                "Standard conversational or transactional business vocabulary",
                "Absence of urgency, extortion, or banking redirection markers"
            ]
        else:
            text_factors.append("General textual and linguistic patterns match the detected threat class.")
            
    # Adversarial factors
    adv_factors = []
    if adversarial_defense and adversarial_defense.get("evasion_detected"):
        zw = adversarial_defense.get("zero_width_chars_removed", 0)
        hg = adversarial_defense.get("homoglyphs_count", 0)
        details = []
        if zw > 0:
            details.append(f"{zw} zero-width invisible char(s) stripped")
        if hg > 0:
            details.append(f"{hg} Unicode homoglyph lookalike(s) normalized")
        adv_factors.append(f"Adversarial evasion attempt neutralized ({', '.join(details)}).")

    # URL factors
    url_factors = []
    if url_results:
        for u in url_results:
            status = u.get("status", "benign")
            url_headline = u.get("analysis_summary", {}).get("headline", status.title())
            if status != "benign":
                url_factors.append(f"Embedded Link Alert: Flagged as {status.upper()} ({url_headline}).")
            else:
                url_factors.append(f"Embedded Link Check: Verified benign/safe by URL Threat Engine.")
                
    combined_factors = text_factors[:3] + adv_factors + [uf for uf in url_factors if "Alert" in uf]
    if not combined_factors:
        combined_factors = text_factors[:3]
        
    return {
        "headline": headline,
        "explanation": explanation,
        "text_factors": text_factors[:4],
        "adversarial_factors": adv_factors,
        "url_factors": url_factors,
        "key_factors": combined_factors
    }

def parse_email_text(raw_text):
    """
    Intelligently splits raw email text into subject and body.
    Detects 'Subject:' headers if present; otherwise uses first line as subject.
    """
    import re
    raw_text = str(raw_text).replace('\r\n', '\n').replace('\r', '\n')
    subject = ""
    body = ""
    
    # Check for explicit Subject: line
    subject_match = re.search(r'(?im)^subject:\s*(.*)$', raw_text)
    if subject_match:
        subject = subject_match.group(1).strip()
        # Remove headers like From:, To:, Subject:, Date: from the body
        clean_body = re.sub(r'(?im)^(from|to|subject|date|cc|bcc):\s*.*$', '', raw_text)
        body = clean_body.strip()
    else:
        # Split by first newline
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if lines:
            subject = lines[0]
            body = "\n".join(lines[1:]) if len(lines) > 1 else lines[0]
            
    return subject, body

WORD_SEMANTIC_REASONS = {
    # Urgency & Coercion
    "required": "Urgent demand compelling recipient compliance",
    "action": "High-priority call-to-action typical in social engineering",
    "immediately": "Pressures recipient to act before verifying legitimacy",
    "urgent": "Fabricates artificial emergency to bypass critical thinking",
    "today": "Imposes an artificial deadline to force hasty action",
    "now": "Demands immediate compliance without standard verification",
    "alert": "Simulates an alarming security warning to induce panic",
    "warning": "Mimics administrative notices to lower recipient skepticism",
    "expires": "Threatens service cutoff or account loss upon deadline",
    "expiration": "Creates fear of imminent service termination",
    "suspended": "Falsely claims service interruption to force compliance",
    "locked": "Triggers fear of lockout to steal credentials",
    "compromised": "Alleges security breach to induce hasty login",
    "unauthorized": "Fabricates suspicious activity to elicit panic",

    # Delivery & Courier Scams
    "hold": "Induces panic over withheld package or missed shipment",
    "package": "Triggers anticipation of expected or undelivered parcel",
    "parcel": "Exploits shipment tracking hooks to solicit fees",
    "delivery": "Simulates courier notification to prompt external clicks",
    "customs": "Fabricates regulatory duties to justify unexpected charges",
    "clearance": "Imposes artificial administrative fee barrier",
    "returned": "Threatens permanent loss of parcel if unpaid",
    "tracking": "Lures user with fabricated parcel tracking reference",

    # Financial & Wire Fraud
    "fee": "Introduces unexpected financial demand or payment obligation",
    "pay": "Directs recipient to execute an unverified monetary transaction",
    "payment": "Prompts user to authorize unverified funds transfer",
    "invoice": "Lures user into billing review to trigger malware or theft",
    "bank": "Targets banking credentials or financial access points",
    "billing": "Prompts urgent review of unverified charges",
    "wire": "Demands irreversible electronic funds transfer",
    "funds": "Solicits financial asset movements or payouts",
    "unpaid": "Alleges outstanding debt to intimidate victim into paying",
    "settle": "Demands immediate payment of fabricated balance",
    "dollars": "Specifies monetary hook to increase perceived urgency",
    
    # Credential Harvesting
    "password": "Attempts to harvest or reset account authentication secrets",
    "reset": "Guides victim to a fraudulent authentication portal",
    "login": "Lures user into entering credentials on fake interface",
    "verify": "Prompts victim to confirm sensitive personal or login data",
    "account": "Targets user access and identity credentials",
    "portal": "Directs recipient to an external untrusted landing page",
    "support": "Impersonates legitimate IT or customer service personnel",
    "credentials": "Directly requests sensitive authentication tokens",
    "link": "Urges victim to navigate away from trusted environment",
    "click": "Commands recipient to trigger untrusted external navigation",
    "access": "Exploits fears of losing corporate network or mailbox access",
    "security": "Leverages authority to make fraudulent requests seem official",
    
    # Commercial & Marketing Spam
    "free": "Offers unsolicited incentive to attract low-effort clicks",
    "discount": "Promotes unsolicited commercial marketing offer",
    "save": "Bulk marketing appeal to drive promotional engagement",
    "offer": "Commercial solicitation designed to generate clicks",
    "deal": "Promotional incentive designed for bulk marketing",
    "reward": "Lures recipient with fabricated contest or gift incentives",
    "gift": "Offers fraudulent retail incentives to gather user info",
    "winner": "Uses lottery or prize claims to initiate advance-fee fraud",
}

def extract_top_xai_tokens(pipeline, input_df, target_class_index, top_n=5) -> list:
    import numpy as np
    try:
        preprocessor = pipeline.named_steps['preprocessor']
        X_trans = preprocessor.transform(input_df)
        feature_names = preprocessor.get_feature_names_out()
        clf_cv = pipeline.named_steps['classifier']
        coefs = np.mean([c.estimator.coef_ for c in clf_cv.calibrated_classifiers_], axis=0)
        
        if coefs.shape[0] == 1:
            target_coef = coefs[0] if target_class_index == 1 else -coefs[0]
        else:
            target_coef = coefs[target_class_index]
            
        activations = X_trans.toarray()[0] if hasattr(X_trans, 'toarray') else X_trans[0]
        token_impact = target_coef * activations
        sorted_indices = np.argsort(token_impact)[::-1]
        
        # Prioritize word-level tokens from Subject and Body
        top_tokens = []
        for idx in sorted_indices:
            if token_impact[idx] > 0.005:
                fname = feature_names[idx]
                if fname.startswith("subject_word__") or fname.startswith("body_word__"):
                    is_subj = fname.startswith("subject_word__")
                    word = fname.replace("subject_word__", "").replace("body_word__", "")
                    loc = "Subject Line" if is_subj else "Email Body"
                    
                    reason = WORD_SEMANTIC_REASONS.get(word.lower())
                    if not reason:
                        for subw in word.lower().split():
                            if subw in WORD_SEMANTIC_REASONS:
                                reason = WORD_SEMANTIC_REASONS[subw]
                                break
                    if not reason:
                        reason = "Pushed model verdict toward threat classification"
                        
                    impact_pct = round(float(token_impact[idx]) * 100, 1)
                    
                    top_tokens.append({
                        "word": word,
                        "location": loc,
                        "impact_pct": impact_pct,
                        "impact_score": round(float(token_impact[idx]), 4),
                        "reason": reason,
                        "token": f"{loc}: \"{word}\""
                    })
                    if len(top_tokens) >= top_n:
                        break
                        
        # Fallback if no word tokens passed threshold
        if not top_tokens:
            for idx in sorted_indices[:top_n]:
                if token_impact[idx] > 0:
                    clean_token = (
                        feature_names[idx]
                        .replace("subject_word__", "Subject: ")
                        .replace("subject_char__", "Subject Char: ")
                        .replace("body_word__", "Body: ")
                        .replace("metadata__scaler__", "Metadata: ")
                        .replace("metadata__", "Metadata: ")
                    )
                    top_tokens.append({
                        "word": clean_token,
                        "location": "Email",
                        "impact_pct": round(float(token_impact[idx]) * 100, 1),
                        "impact_score": round(float(token_impact[idx]), 4),
                        "reason": "Elevated baseline numerical threat features",
                        "token": clean_token
                    })
        return top_tokens
    except Exception:
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Predict if an email is safe, spam, or phishing.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  1. Passing full email text directly:
     python predict_email.py "Subject: Claim your reward!\\n\\nClick here to win a gift card."

  2. Passing subject and body separately:
     python predict_email.py --subject "Meeting notes" --body "Attached are the notes from today."
        """
    )
    parser.add_argument("email_text", nargs="?", default=None, help="Full raw email text (subject and body combined)")
    parser.add_argument("--subject", type=str, default=None, help="The email subject line")
    parser.add_argument("--body", type=str, default=None, help="The email body content")
    parser.add_argument("--raw", type=str, default=None, help="Raw email text with headers")
    args = parser.parse_args()
    
    # Determine subject and body based on provided inputs
    raw_input = args.email_text or args.raw
    
    if args.subject is not None or args.body is not None:
        subject = args.subject or ""
        body = args.body or ""
    elif raw_input:
        subject, body = parse_email_text(raw_input)
    else:
        parser.print_help()
        return
        
    subject, subj_telemetry = sanitize_adversarial_text(subject)
    body, body_telemetry = sanitize_adversarial_text(body)
    
    adversarial_defense = {
        "evasion_detected": subj_telemetry["evasion_detected"] or body_telemetry["evasion_detected"],
        "zero_width_chars_removed": subj_telemetry["zero_width_chars_removed"] + body_telemetry["zero_width_chars_removed"],
        "homoglyphs_normalized": subj_telemetry["homoglyphs_normalized"] or body_telemetry["homoglyphs_normalized"],
        "homoglyphs_count": subj_telemetry.get("homoglyphs_count", 0) + body_telemetry.get("homoglyphs_count", 0)
    }
        
    extractor = URLExtract()
    extracted_urls = extractor.find_urls(subject + " " + body)
        
    url_results = []
    highest_url_threat = "benign"
    
    if predict_url and extracted_urls:
        evaluate = input("Do you want to evaluate these extracted URLs with the URL Threat Engine? (y/n): ").strip().lower()
        if evaluate == 'y':
            for url in extracted_urls:
                try:
                    url_pred = predict_url(url)
                    url_results.append(url_pred)
                    status = url_pred.get("status", "benign")
                    if status == "malware":
                        highest_url_threat = "malware"
                    elif status == "phishing" and highest_url_threat != "malware":
                        highest_url_threat = "phishing"
                    elif status == "defacement" and highest_url_threat == "benign":
                        highest_url_threat = "defacement"
                except Exception:
                    pass
        
    model_legacy_path = os.path.join(os.path.dirname(__file__), 'models', 'model_legacy.pkl')
    model_modern_path = os.path.join(os.path.dirname(__file__), 'models', 'model_modern.pkl')
    
    if not os.path.exists(model_legacy_path) or not os.path.exists(model_modern_path):
        print(json.dumps({"error": "Dual-engine models not found. Please run train_dual_engine.py first."}))
        return
        
    model_legacy_data = joblib.load(model_legacy_path)
    pipeline_legacy = model_legacy_data['pipeline']
    le_legacy = model_legacy_data['label_encoder']

    model_modern_data = joblib.load(model_modern_path)
    pipeline_modern = model_modern_data['pipeline']
    le_modern = model_modern_data['label_encoder']
    
    input_df = pd.DataFrame({'subject': [subject], 'body': [body]})
    
    extractor_meta = MetadataExtractor()
    features_df = extractor_meta.transform(input_df)
    email_features_dict = features_df.iloc[0].to_dict()
    
    probs_legacy = pipeline_legacy.predict_proba(input_df)[0]
    probs_modern = pipeline_modern.predict_proba(input_df)[0]
    
    dict_legacy = {cls: prob for cls, prob in zip(le_legacy.classes_, probs_legacy)}
    dict_modern = {cls: prob for cls, prob in zip(le_modern.classes_, probs_modern)}
    
    classes = sorted(list(set(le_legacy.classes_) | set(le_modern.classes_)))
    
    fused_probs = {}
    for cls in classes:
        l_prob = dict_legacy.get(cls, 0.0)
        m_prob = dict_modern.get(cls, 0.0)
        fused_probs[cls] = (l_prob * 0.40) + (m_prob * 0.60)
        
    statistical_prediction = max(fused_probs, key=fused_probs.get)
    probabilities = [fused_probs[cls] for cls in classes]
    
    # Run Semantic Threat & Behavioral Arbiter
    bec_hits, spam_hits = scan_semantic_threats(subject, body)
    
    is_hybrid_override = False
    threat_factors = []
    
    if bec_hits:
        prediction = "phishing"
        is_hybrid_override = True
        threat_factors = bec_hits
        class_probabilities = {
            "phishing": 99.85,
            "safe": 0.10,
            "spam": 0.05
        }
    elif spam_hits:
        prediction = "spam"
        is_hybrid_override = True
        threat_factors = spam_hits
        class_probabilities = {
            "spam": 99.70,
            "safe": 0.20,
            "phishing": 0.10
        }
    else:
        prediction = statistical_prediction
        threat_factors = []
        class_probabilities = {
            str(cls): float(round(prob * 100, 2))
            for cls, prob in zip(classes, probabilities)
        }
        
    fusion_triggered = False
    fusion_reason = ""
    
    if highest_url_threat == "malware":
        prediction = "phishing"
        is_hybrid_override = True
        fusion_triggered = True
        fusion_reason = "URL Fusion: Confirmed MALWARE payload delivery link."
        class_probabilities = {"phishing": 99.99, "safe": 0.0, "spam": 0.01}
        
    elif prediction != "phishing" and highest_url_threat == "phishing":
        prediction = "phishing"
        is_hybrid_override = True
        fusion_triggered = True
        fusion_reason = "URL Fusion: Confirmed credential harvesting link detected."
        class_probabilities = {"phishing": 99.90, "safe": 0.05, "spam": 0.05}
        
    elif fused_probs.get("phishing", 0.0) > 0.45 and highest_url_threat != "benign":
        prediction = "phishing"
        is_hybrid_override = True
        fusion_triggered = True
        fusion_reason = f"URL Synergy: Elevated textual risk ({fused_probs.get('phishing', 0.0)*100:.1f}%) combined with {highest_url_threat.upper()} URL."
        class_probabilities = {"phishing": 98.00, "safe": 1.00, "spam": 1.00}
            
    analysis_summary = generate_analysis_summary(
        prediction, 
        subject, 
        body, 
        threat_factors=threat_factors,
        adversarial_defense=adversarial_defense,
        url_results=url_results
    )
    
    # Extract raw margin from LinearSVC inside CalibratedClassifierCV
    try:
        import numpy as np
        # Average margin from both engines
        X_trans_legacy = pipeline_legacy.named_steps['preprocessor'].transform(input_df)
        clf_cv_legacy = pipeline_legacy.named_steps['classifier']
        margins_legacy = [c.estimator.decision_function(X_trans_legacy)[0] for c in clf_cv_legacy.calibrated_classifiers_]
        
        X_trans_modern = pipeline_modern.named_steps['preprocessor'].transform(input_df)
        clf_cv_modern = pipeline_modern.named_steps['classifier']
        margins_modern = [c.estimator.decision_function(X_trans_modern)[0] for c in clf_cv_modern.calibrated_classifiers_]
        
        margin = float(np.mean([np.max(m) for m in margins_legacy + margins_modern]))
    except Exception:
        margin = 0.0

    legacy_str = ", ".join([f"{cls}: {round(float(dict_legacy.get(cls, 0.0))*100, 2)}%" for cls in classes])
    modern_str = ", ".join([f"{cls}: {round(float(dict_modern.get(cls, 0.0))*100, 2)}%" for cls in classes])
    fused_str = ", ".join([f"{cls}: {round(float(fused_probs.get(cls, 0.0))*100, 2)}%" for cls in classes])

    step_by_step = [
        f"Step 1: Adversarial Text Normalization - Homoglyphs Normalized: {adversarial_defense['homoglyphs_normalized']} ({adversarial_defense.get('homoglyphs_count', 0)} lookalike(s)) | Zero-Width Chars Stripped: {adversarial_defense['zero_width_chars_removed']}.",
        f"Step 2: Decoupled Feature Extraction - TF-IDF n-grams (subject & body) & numerical metadata ratios.",
        f"Step 3: Dual-Engine Hyperplane Evaluation - Legacy Model ({legacy_str}) | Modern Model ({modern_str}).",
        f"Step 4: Asymmetric Soft-Voting Ensemble (40% Legacy / 60% Modern) - Consensus ({fused_str}) -> Baseline Prediction: {statistical_prediction.upper()}."
    ]
    if is_hybrid_override:
        if threat_factors:
            step_by_step.append(f"Step 5a: Semantic Threat & Behavioral Arbiter Violation -> '{threat_factors[0][1]}'.")
        if fusion_triggered:
            step_by_step.append(f"Step 5b: Multi-Modal URL Fusion Engine Override -> {fusion_reason}")
        step_by_step.append(f"Step 6: Defense-in-Depth Policy Escalation -> Final Classification: {prediction.upper()}.")

    mathematical_breakdown = {
        "formula": "Hybrid Defense: P(threat|x, z) = Alpha * P_SVM(y|x) + (1 - Alpha) * Indicator_Policy(z)",
        "baseline_nlp_prediction": statistical_prediction,
        "security_policy_override": is_hybrid_override,
        "raw_margin_f_x": round(margin, 3),
        "ensemble_weights": {"legacy": 0.40, "modern": 0.60},
        "engine_breakdown": {
            "legacy": {str(cls): round(float(dict_legacy.get(cls, 0.0)) * 100, 2) for cls in classes},
            "modern": {str(cls): round(float(dict_modern.get(cls, 0.0)) * 100, 2) for cls in classes}
        },
        "class_probabilities_raw": {
            str(cls): round(float(class_probabilities[str(cls)] / 100.0), 4)
            for cls in classes
        },
        "step_by_step": step_by_step
    }
        
    threat_intelligence = {
        "technique_id": "N/A",
        "technique_name": "N/A",
        "severity": "Informational" if prediction == "safe" else "Medium",
        "recommended_action": "None" if prediction == "safe" else "Review"
    }
    
    if is_hybrid_override and threat_factors:
        mitre_hit = threat_factors[0]
        threat_intelligence = {
            "technique_id": mitre_hit[2],
            "technique_name": mitre_hit[3],
            "severity": mitre_hit[4],
            "recommended_action": "Quarantine and isolate" if mitre_hit[4] == "Critical" else "Mark as Spam"
        }

    target_class_idx = list(le_modern.classes_).index(prediction) if prediction in le_modern.classes_ else 0
    top_tokens = extract_top_xai_tokens(pipeline_modern, input_df, target_class_idx)
    
    explainable_ai = {
        "top_contributing_tokens": top_tokens,
        "model_transparency": f"LinearSVC coefficients multiplied by {prediction} feature activations"
    }
        
    response = {
        "status": prediction,
        "threat_intelligence": threat_intelligence,
        "explainable_ai": explainable_ai,
        "adversarial_defense": adversarial_defense,
        "class_probabilities": class_probabilities,
        "analysis_summary": analysis_summary,
        "mathematical_breakdown": mathematical_breakdown,
        "extracted_urls": extracted_urls,
        "url_threat_level": highest_url_threat,
        "detailed_url_analysis": url_results,
        "extracted_features": email_features_dict
    }
        
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    
    console = Console()
    
    # [ EMAIL TEXT ANALYSIS & MATHEMATICS ]
    console.print(Panel(Text("EMAIL TEXT ANALYSIS & MATHEMATICS", justify="center", style="bold blue"), box=box.DOUBLE))
    
    # Overview Table
    overview_table = Table(show_header=False, box=box.ROUNDED)
    overview_table.add_row("Formula:", "P_fused(c) = 0.40 * P_legacy(c) + 0.60 * P_modern(c)")
    overview_table.add_row("Base NLP Prediction:", response['mathematical_breakdown']['baseline_nlp_prediction'].upper())
    overview_table.add_row("Policy Override:", 'YES' if response['mathematical_breakdown']['security_policy_override'] else 'NO')
    console.print(overview_table)
    
    # Dual-Engine Class Probabilities Table
    prob_table = Table(title="Dual-Engine Class Probabilities", title_style="bold magenta", box=box.ROUNDED)
    prob_table.add_column("Engine", style="blue")
    prob_table.add_column("Probabilities", style="black")
    
    legacy_breakdown = ", ".join([f"{k}: {v}%" for k, v in response['mathematical_breakdown']['engine_breakdown']['legacy'].items()])
    modern_breakdown = ", ".join([f"{k}: {v}%" for k, v in response['mathematical_breakdown']['engine_breakdown']['modern'].items()])
    final_probs_str = ", ".join([f"{k}: {v}%" for k, v in response['class_probabilities'].items()])
    
    prob_table.add_row("Legacy Engine (40%)", legacy_breakdown)
    prob_table.add_row("Modern Engine (60%)", modern_breakdown)
    prob_table.add_row("Final Class Probs", final_probs_str)
    console.print(prob_table)
    
    # Adversarial Metrics Table
    adv_table = Table(title="Adversarial Metrics", title_style="bold red", box=box.ROUNDED)
    adv_table.add_column("Metric", style="blue")
    adv_table.add_column("Value", style="magenta")
    
    hg_note = f" ({response['adversarial_defense'].get('homoglyphs_count', 0)} detected & normalized)" if response['adversarial_defense']['homoglyphs_normalized'] else ""
    adv_table.add_row("Homoglyphs Normalized", f"{response['adversarial_defense']['homoglyphs_normalized']}{hg_note}")
    adv_table.add_row("Zero-Width Chars", str(response['adversarial_defense']['zero_width_chars_removed']))
    evasion_str = "YES (Adversarial Evasion Defeated)" if response['adversarial_defense']['evasion_detected'] else "False"
    adv_table.add_row("Evasion Detected", evasion_str)
    console.print(adv_table)
    
    # Explainable AI Table
    xai_table = Table(title="Explainable AI (Why the Model Flagged This Email)", title_style="bold magenta", box=box.ROUNDED)
    xai_table.add_column("No.", style="bold black")
    xai_table.add_column("Token", style="blue")
    xai_table.add_column("Location", style="magenta")
    xai_table.add_column("Reason", style="black")
    xai_table.add_column("Influence", style="red")
    
    top_toks = response['explainable_ai']['top_contributing_tokens']
    if top_toks:
        for i, item in enumerate(top_toks, 1):
            w = f"\"{item.get('word', item.get('token'))}\""
            loc = item.get('location', 'Email')
            pct = item.get('impact_pct', round(item.get('impact_score', 0)*100, 1))
            reason = item.get('reason', 'Pushed classification toward threat')
            xai_table.add_row(str(i), w, loc, reason, f"+{pct}%")
    else:
        xai_table.add_row("-", "None", "-", "No single linguistic word token exceeded the threat threshold", "-")
    console.print(xai_table)
    
    # Extracted Email Features Table
    feat_table = Table(title="Extracted Email Features (Metadata)", title_style="bold blue", box=box.ROUNDED)
    feat_table.add_column("Feature", style="blue")
    feat_table.add_column("Value", style="black")
    sorted_email_feats = sorted([(k, v) for k, v in response['extracted_features'].items() if v > 0], key=lambda x: x[1], reverse=True)
    if sorted_email_feats:
        for k, v in sorted_email_feats:
            feat_table.add_row(k.replace('_', ' ').title(), str(round(v, 4)))
    else:
        feat_table.add_row("None", "No significant numerical features extracted")
    console.print(feat_table)
    
    # Voting Weights & SVM Margin Table
    svm_table = Table(title="Voting Weights & SVM Margin", title_style="bold magenta", box=box.ROUNDED)
    svm_table.add_column("Metric", style="blue")
    svm_table.add_column("Value", style="magenta")
    svm_table.add_row("Legacy Engine Weight", f"{response['mathematical_breakdown']['ensemble_weights']['legacy'] * 100}%")
    svm_table.add_row("Modern Engine Weight", f"{response['mathematical_breakdown']['ensemble_weights']['modern'] * 100}%")
    svm_table.add_row("Raw SVM Margin f(x)", str(response['mathematical_breakdown']['raw_margin_f_x']))
    console.print(svm_table)
    
    # Step-by-Step Mathematics & Decision Process
    step_table = Table(title="Step-by-Step Mathematics & Decision Process", title_style="bold black", show_header=False, box=box.ROUNDED)
    step_table.add_column("Step", style="black")
    for step in response['mathematical_breakdown']['step_by_step']:
        step_table.add_row(f"- {step}")
    console.print(step_table)
    
    # URL THREAT ENGINE ANALYSIS & MATHEMATICS
    if response.get('detailed_url_analysis'):
        console.print(Panel(Text("URL THREAT ENGINE ANALYSIS & MATHEMATICS", justify="center", style="bold blue"), box=box.DOUBLE))
        console.print("Formula: [bold]P(k) = e^(z_k) / Sum(e^(z_j))[/bold]  [bold black][Softmax Normalization][/bold black]\n")
        
        for i, url_res in enumerate(response['detailed_url_analysis']):
            url_str = response['extracted_urls'][i] if i < len(response['extracted_urls']) else 'Unknown'
            url_table = Table(title=f"URL: {url_str}", title_style="bold magenta", box=box.ROUNDED)
            url_table.add_column("Metric", style="blue")
            url_table.add_column("Value", style="black")
            
            url_table.add_row("Status", f"[bold red]{url_res.get('status', 'Unknown').upper()}[/bold red]")
            probs = url_res.get('class_probabilities', {})
            if probs:
                prob_str = ", ".join([f"{k}: {v}%" for k, v in probs.items()])
                url_table.add_row("Class Probabilities", prob_str)
            
            math_breakdown = url_res.get('mathematical_breakdown', {})
            if math_breakdown:
                url_table.add_row("Logits", str(math_breakdown.get('raw_logits_z', {})))
                url_table.add_row("Exponentials", str(math_breakdown.get('exponentials_exp_z', {})))
                url_table.add_row("Sum Denominator", str(math_breakdown.get('sum_denominator', 'N/A')))
            
            console.print(url_table)
            
            # Step-by-Step
            if math_breakdown.get('step_by_step'):
                u_step_table = Table(title="Softmax Step-by-Step", title_style="bold black", show_header=False, box=box.ROUNDED)
                u_step_table.add_column("Step", style="bold black")
                for step in math_breakdown.get('step_by_step', []):
                    u_step_table.add_row(f"- {step}")
                console.print(u_step_table)
            
            # URL Explanation & Key Factors
            url_summary = url_res.get('analysis_summary', {})
            if url_summary:
                u_expl_table = Table(title="URL Threat Explanation & Key Factors", title_style="bold red", box=box.ROUNDED)
                u_expl_table.add_column("Detail", style="blue")
                u_expl_table.add_column("Information", style="black")
                u_expl_table.add_row("Headline", url_summary.get('headline', 'N/A'))
                u_expl_table.add_row("Explanation", url_summary.get('explanation', 'N/A'))
                
                url_kf = url_summary.get('key_factors', [])
                if url_kf:
                    kf_str = "\n".join([f"- {kf}" for kf in url_kf])
                    u_expl_table.add_row("Key Risk Factors", kf_str)
                console.print(u_expl_table)
            console.print("-" * 40)
            
    # FINAL COMBINED VERDICT
    console.print(Panel(Text("FINAL COMBINED VERDICT", justify="center", style="bold red"), box=box.DOUBLE))
    
    final_table = Table(show_header=False, box=box.ROUNDED)
    final_table.add_column("Property", style="bold blue")
    final_table.add_column("Value", style="bold black")
    
    final_status = response['status'].upper()
    status_color = "red" if final_status in ["PHISHING", "MALWARE"] else ("yellow" if final_status == "SPAM" else "green")
    
    final_table.add_row("ABSOLUTE DECISION:", f"[{status_color}]{final_status}[/{status_color}]")
    final_table.add_row("Threat Severity:", response['threat_intelligence']['severity'])
    final_table.add_row("Recommended Action:", response['threat_intelligence']['recommended_action'])
    final_table.add_row("MITRE Technique:", f"{response['threat_intelligence']['technique_id']} - {response['threat_intelligence']['technique_name']}")
    console.print(final_table)
    
    summary = response['analysis_summary']
    if isinstance(summary, dict):
        syn_table = Table(title="Key Security Factors (Synthesized Across All Modalities)", title_style="bold blue", box=box.ROUNDED)
        syn_table.add_column("Modality", style="blue")
        syn_table.add_column("Factors", style="black")
        
        if summary.get('text_factors'):
            tf_str = "\n".join([f"- {factor}" for factor in summary.get('text_factors', [])])
            syn_table.add_row("Email Text Analysis", tf_str)
        if summary.get('adversarial_factors'):
            af_str = "\n".join([f"- {factor}" for factor in summary.get('adversarial_factors', [])])
            syn_table.add_row("Adversarial Defense Telemetry", af_str)
        if summary.get('url_factors'):
            uf_str = "\n".join([f"- {factor}" for factor in summary.get('url_factors', [])])
            syn_table.add_row("URL Threat Engine Analysis", uf_str)
        console.print(syn_table)
        
        exp_table = Table(title="Comprehensive Final Explanation", title_style="bold magenta", box=box.ROUNDED)
        exp_table.add_column("Field", style="blue")
        exp_table.add_column("Text", style="black")
        exp_table.add_row("Headline", summary.get('headline', ''))
        exp_table.add_row("Explanation", summary.get('explanation', ''))
        console.print(exp_table)
        
    elif isinstance(summary, list):
        for summary_line in summary:
            console.print(summary_line)
    else:
        console.print(summary)

if __name__ == "__main__":
    main()