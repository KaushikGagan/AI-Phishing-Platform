"""
dataset_trainer.py — retrain the phishing NLP classifier on any dataset.

Usage:
    py dataset_trainer.py
    py dataset_trainer.py --kaggle path/to/emails.csv
    py dataset_trainer.py --spam-dir path/to/spam --ham-dir path/to/ham
    py dataset_trainer.py --phishtank
"""
import sys
import os
import argparse
import pickle

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_loader import load_all
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "nlp_model.pkl")


def train(data: list[dict], save: bool = True) -> dict:
    texts = [d["text"] for d in data]
    labels = [d["label"] for d in data]

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42,
        stratify=labels if len(set(labels)) > 1 else None
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=8000,
            sublinear_tf=True,
            min_df=1
        )),
        ("clf", RandomForestClassifier(
            n_estimators=150,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        ))
    ])

    print("[*] Training model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=["safe", "phishing"],
        output_dict=True,
        zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred)

    cv_scores = cross_val_score(pipeline, texts, labels, cv=min(5, len(set(labels))*2), scoring="f1")

    print("\n[+] Evaluation Results:")
    print(f"    Accuracy  : {report['accuracy']:.4f}")
    print(f"    Precision : {report['phishing']['precision']:.4f}")
    print(f"    Recall    : {report['phishing']['recall']:.4f}")
    print(f"    F1 Score  : {report['phishing']['f1-score']:.4f}")
    print(f"    CV F1 Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    print(f"\n    Confusion Matrix:\n{cm}")

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)
        print(f"\n[+] Model saved to {MODEL_PATH}")

    return {
        "pipeline": pipeline,
        "report": report,
        "cm": cm.tolist(),
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "train_size": len(X_train),
        "test_size": len(X_test),
    }


def main():
    parser = argparse.ArgumentParser(description="Retrain PhishGuard NLP model")
    parser.add_argument("--kaggle", type=str, default=None,
                        help="Path to Kaggle phishing email CSV")
    parser.add_argument("--spam-dir", type=str, default=None,
                        help="Path to SpamAssassin spam folder")
    parser.add_argument("--ham-dir", type=str, default=None,
                        help="Path to SpamAssassin ham folder")
    parser.add_argument("--phishtank", action="store_true",
                        help="Download and include PhishTank URL feed")
    parser.add_argument("--no-save", action="store_true",
                        help="Do not save the trained model")
    args = parser.parse_args()

    print("[*] Loading datasets...")
    data = load_all(
        kaggle_csv=args.kaggle,
        spamassassin_spam_dir=args.spam_dir,
        spamassassin_ham_dir=args.ham_dir,
        include_phishtank=args.phishtank,
    )

    if len(data) < 10:
        print("[!] Not enough data to train. Minimum 10 samples required.")
        sys.exit(1)

    result = train(data, save=not args.no_save)
    print("\n[+] Training complete.")
    return result


if __name__ == "__main__":
    main()
