from __future__ import annotations
import argparse
import os
import random
from typing import List
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from feature_extraction import FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "ransomware_lgbm.txt")


def _benign_window():
    if random.random() < 0.25:
        files_touched = max(4, int(random.gauss(15, 8)))
        writes = max(2, int(random.gauss(files_touched * 0.7, 4)))
        renames = max(2, int(random.gauss(files_touched * 0.5, 4)))
        deletes = max(0, int(random.gauss(0.5, 1)))
        creates = max(0, int(random.gauss(1, 1.5)))
        mean_entropy_delta = random.gauss(0.08, 0.2)
        max_entropy_delta = mean_entropy_delta + abs(random.gauss(0.15, 0.2))
        ext_change_rate = max(0.0, min(1.0, random.gauss(0.04, 0.05)))
        unique_dirs = max(1, int(random.gauss(2, 1.5)))
        events_per_second = max(0.5, random.gauss(5, 3))
        high_entropy_write_rate = max(0.0, min(1.0, random.gauss(0.04, 0.05)))
    else:
        files_touched = max(1, int(random.gauss(3, 3)))
        writes = max(0, int(random.gauss(files_touched * 0.6, 2)))
        renames = max(0, int(random.gauss(0.3, 0.6)))
        deletes = max(0, int(random.gauss(0.2, 0.5)))
        creates = max(0, int(random.gauss(0.5, 1)))
        mean_entropy_delta = random.gauss(0.05, 0.15)
        max_entropy_delta = mean_entropy_delta + abs(random.gauss(0.1, 0.2))
        ext_change_rate = max(0.0, min(1.0, random.gauss(0.02, 0.05)))
        unique_dirs = max(1, int(random.gauss(1.5, 1)))
        events_per_second = max(0.0, random.gauss(1.0, 1.5))
        high_entropy_write_rate = max(0.0, min(1.0, random.gauss(0.03, 0.05)))

    return [
        files_touched, writes, renames, deletes, creates,
        mean_entropy_delta, max_entropy_delta, ext_change_rate,
        unique_dirs, events_per_second, high_entropy_write_rate,
    ]


def _ransomware_like_window() -> List[float]:
    files_touched = max(5, int(random.gauss(60, 25)))
    writes = max(5, int(random.gauss(files_touched * 0.95, 10)))
    renames = max(5, int(random.gauss(files_touched * 0.9, 10)))
    deletes = max(0, int(random.gauss(2, 2)))
    creates = max(0, int(random.gauss(1, 1)))
    mean_entropy_delta = random.gauss(3.5, 1.0)         # big jump toward randomness
    max_entropy_delta = mean_entropy_delta + abs(random.gauss(1.0, 0.5))
    ext_change_rate = max(0.0, min(1.0, random.gauss(0.9, 0.1)))
    unique_dirs = max(1, int(random.gauss(8, 4)))
    events_per_second = max(1.0, random.gauss(40, 15))
    high_entropy_write_rate = max(0.0, min(1.0, random.gauss(0.85, 0.1)))
    
    return [
        files_touched, writes, renames, deletes, creates,
        mean_entropy_delta, max_entropy_delta, ext_change_rate,
        unique_dirs, events_per_second, high_entropy_write_rate,
    ]


def generate_synthetic_dataset(n_benign: int = 4000, n_malicious: int = 1000, seed: int = 7):
    random.seed(seed)
    rows = []
    for _ in range(n_benign):
        rows.append(_benign_window() + [0])
    for _ in range(n_malicious):
        rows.append(_ransomware_like_window() + [1])
    df = pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def load_real_logs(csv_path: str):
    df = pd.read_csv(csv_path)
    missing = set(FEATURE_NAMES + ["label"]) - set(df.columns)
    if missing:
        raise ValueError(f"Log file missing columns: {missing}")
    return df


def train(df: pd.DataFrame, model_path: str = MODEL_PATH):
    X = df[FEATURE_NAMES]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=7
    )

    train_set = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
    val_set = lgb.Dataset(X_test, label=y_test, feature_name=FEATURE_NAMES, reference=train_set)

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "verbosity": -1,
        "num_leaves": 15,
        "learning_rate": 0.08,
        "min_data_in_leaf": 20,
    }

    booster = lgb.train(
        params,
        train_set,
        num_boost_round=200,
        valid_sets=[val_set],
        callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)],
    )

    preds = booster.predict(X_test, num_iteration=booster.best_iteration)
    pred_labels = (preds >= 0.5).astype(int)

    print(f"AUC: {roc_auc_score(y_test, preds):.4f}")
    print(classification_report(y_test, pred_labels, target_names=["benign", "malicious"]))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    booster.save_model(model_path)
    print(f"Saved model to {model_path}")
    return booster

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--real-logs",
        type=str,
        default=None,
        help="Path to a CSV of real sandbox-derived window features. "
             "Omit to train on the synthetic generator instead.",
    )
    parser.add_argument("--n-benign", type=int, default=4000)
    parser.add_argument("--n-malicious", type=int, default=1000)
    args = parser.parse_args()

    if args.real_logs:
        dataset = load_real_logs(args.real_logs)
    else:
        print("No --real-logs given, training on the synthetic generator.")
        dataset = generate_synthetic_dataset(args.n_benign, args.n_malicious)

    train(dataset)