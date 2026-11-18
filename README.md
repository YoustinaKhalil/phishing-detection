# Phishing URL Detector

Random-Forest model on URL features + input validation + safety rules.
FastAPI backend (`main.py`) and Streamlit UI (`app.py`).

## Files
| File | Role |
|---|---|
| `features.py` | Feature extraction - must match training exactly |
| `validation.py` | Cleans input, rejects non-links (Arabic text, "google"…), safety rules, trusted list |
| `detector.py` | Loads the model and returns `safe / suspicious / phishing` |
| `main.py` | FastAPI: `POST /predict` (`422` when the input isn't a link) |
| `app.py` | Streamlit UI |
| `test_cases.py` | `python test_cases.py` - edge cases (Arabic, IP, look-alike domains…) |
| `Final_model.pkl`, `model_scaler.pkl` | Trained model + scaler |
| `trusted_domains.txt` | Optional extra trusted domains |

## Run
```bash
pip install -r requirements.txt
uvicorn main:app --port 8000        # terminal 1
streamlit run app.py                # terminal 2  (set API_URL if the API is elsewhere)
python test_cases.py                # sanity tests
```
