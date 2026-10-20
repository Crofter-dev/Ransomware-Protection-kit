from __future__ import annotations
import argparse
import warnings
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from feature_extraction import FEATURE_NAMES

warnings.filterwarnings("ignore")

MODELS = {
    "lightgbm": lambda: LGBMClassifier(
        n_estimators=200, learning_rate=0.05, num_leaves=7,
        min_child_samples=5, verbosity=-1, random_state=7,
    ),
    "random_forest": lambda: RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, random_state=7, n_jobs=-1,
    ),
    "logistic_regression": lambda: make_pipeline(
        StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"),
    ),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    X, y, groups = df[FEATURE_NAMES], df["label"], df["scenario"]
    print(f"{len(df)} windows | {int(y.sum())} attack | {int((1 - y).sum())} normal | "
          f"{groups.nunique()} scenarios\n")

    cv = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=7)
    folds = list(cv.split(X, y, groups))

    results = {}
    for name, make in MODELS.items():
        oof = np.zeros(len(df))
        for train_idx, test_idx in folds:
            model = make().fit(X.iloc[train_idx], y.iloc[train_idx])
            oof[test_idx] = model.predict_proba(X.iloc[test_idx])[:, 1]
        pred = (oof >= args.threshold).astype(int)
        results[name] = oof
        print(f"{name:20s} AUC={roc_auc_score(y, oof):.3f}  "
              f"precision={precision_score(y, pred):.3f}  "
              f"recall={recall_score(y, pred):.3f}  F1={f1_score(y, pred):.3f}")

    print("\nPer scenario type (share of windows the model gets right, "
          f"threshold {args.threshold}):")
    kinds = sorted(df["kind"].unique())
    table = pd.DataFrame(index=kinds, columns=list(MODELS))
    for name, oof in results.items():
        pred = (oof >= args.threshold).astype(int)
        for k in kinds:
            mask = (df["kind"] == k).values
            table.loc[k, name] = f"{(pred[mask] == y[mask].values).mean():.2f}"
    table.insert(0, "windows", [int((df["kind"] == k).sum()) for k in kinds])
    table.insert(1, "label", [int(df.loc[df["kind"] == k, "label"].iloc[0]) for k in kinds])
    print(table.to_string())

if __name__ == "__main__":
    main()