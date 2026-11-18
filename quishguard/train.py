"""Train the optional QuishGuard ML model for phishing URL detection."""

from __future__ import annotations

import argparse
import json

from app.ml import MODEL_PATH, train_and_save_model


def main() -> int:
    """Train and save the phishing model, then print the metrics summary."""
    parser = argparse.ArgumentParser(description="Train the QuishGuard ML phishing detector.")
    parser.add_argument("--dataset", default=None, help="Optional CSV dataset with url,label columns.")
    parser.add_argument("--output", default=str(MODEL_PATH), help="Output model path for the trained artifact.")
    args = parser.parse_args()

    metrics = train_and_save_model(dataset_path=args.dataset, output_path=args.output)
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
