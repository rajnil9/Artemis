"""
Artemis Email Model Training Pipeline.
Trains multi-class classifier for legitimate, spam, and phishing email detection.
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
# pyrefly: ignore [missing-import]
import joblib
import os

from email_features import extract_email_metadata

def main():
    # ---------------------------------------------------------
    # STEP 1: LOAD THE DATASET
    # ---------------------------------------------------------
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'Phishing_Email.csv')
    print(f"Reading dataset from {dataset_path}...")
    
    df = pd.read_csv(dataset_path)
    
    # Drop NaN values in Email Text or Email Type
    df = df.dropna(subset=['Email Text', 'Email Type'])
    
    # Map 'Safe Email' to 'ham' and 'Phishing Email' to 'phishing'
    label_mapping = {'Safe Email': 'ham', 'Phishing Email': 'phishing'}
    df['label'] = df['Email Type'].map(label_mapping)
    
    # Drop any rows where mapping failed (if any)
    df = df.dropna(subset=['label'])
    
    # ---------------------------------------------------------
    # STEP 2: MULTI-MODAL FEATURE EXTRACTION
    # ---------------------------------------------------------
    print("Extracting multi-modal features (URLs, Length, Uppercase Ratio, etc.)...")
    X = extract_email_metadata(df['Email Text'])
    y = df['label'].copy()
    
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # ---------------------------------------------------------
    # STEP 3: DATA SPLITTING
    # ---------------------------------------------------------
    print("Splitting dataset into training and testing sets (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded)
    
    # ---------------------------------------------------------
    # STEP 4: COLUMN TRANSFORMER & PIPELINE SETUP
    # ---------------------------------------------------------
    print("Building Multi-Modal NLP Pipeline (TF-IDF + Numerical Metadata + LinearSVC)...")
    
    # Select all numerical features dynamically (everything except 'text')
    num_cols = [col for col in X_train.columns if col != 'text']
    
    # We use a ColumnTransformer to apply TF-IDF only to the 'text' column (max 5000 features), 
    # and pass all numerical metadata features straight through.
    preprocessor = ColumnTransformer(
        transformers=[
            ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english'), 'text'),
            ('num_features', 'passthrough', num_cols)
        ]
    )
    
    # Initialize base model
    base_svc = LinearSVC(class_weight='balanced', random_state=42, max_iter=2000)
    # Wrap in calibrator
    calibrated_svc = CalibratedClassifierCV(estimator=base_svc, method='sigmoid', cv=3)
    
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', calibrated_svc)
    ])
    
    # ---------------------------------------------------------
    # STEP 5: TRAINING & CROSS-VALIDATION
    # ---------------------------------------------------------
    print("Training the Calibrated LinearSVC Email Spam model...")
    pipeline.fit(X_train, y_train)
    
    print("Performing 3-fold cross-validation on training data...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=3, n_jobs=-1)
    print(f"Cross-Validation Mean Accuracy: {cv_scores.mean():.4f}")

    # ---------------------------------------------------------
    # STEP 6: EVALUATION
    # ---------------------------------------------------------
    print("\nClassification Report (Test Set):")
    predictions = pipeline.predict(X_test)
    print(classification_report(y_test, predictions, target_names=label_encoder.classes_))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    
    # ---------------------------------------------------------
    # STEP 7: EXPORT THE MODEL
    # ---------------------------------------------------------
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, 'email_spam_model.pkl')
    model_artifact = {
        'pipeline': pipeline,
        'label_encoder': label_encoder
    }
    joblib.dump(model_artifact, model_path)
    print(f"\nMulti-Modal Email Spam Pipeline saved to {model_path}")

if __name__ == "__main__":
    main()