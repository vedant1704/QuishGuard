from app.ml import extract_url_features, predict_url_risk, train_and_save_model


def test_extract_url_features_for_phishing_fallback() -> None:
    features = extract_url_features("https://paytm-secure-login-verify-kyc.com/verify")

    assert len(features) >= 8
    assert features[0] > 0
    assert features[1] >= 2
    assert features[2] >= 1
    assert features[3] >= 0


def test_train_and_save_model_creates_artifact(tmp_path) -> None:
    output_path = tmp_path / "ml_model.joblib"
    metrics = train_and_save_model(output_path=output_path)

    assert "RandomForest" in metrics
    assert "XGBoost" in metrics
    assert output_path.exists()


def test_predict_url_risk_returns_probability() -> None:
    probability = predict_url_risk("https://paytm-secure-login-verify-kyc.com/verify")

    assert 0.0 <= probability <= 1.0
