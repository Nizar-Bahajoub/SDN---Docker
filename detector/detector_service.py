# detector/detector_service.py
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn, os, joblib, numpy as np

app = FastAPI()
MODEL_PATH = os.getenv("MODEL_PATH", "/models/model.pkl")
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("Loaded model", MODEL_PATH)
    except Exception as e:
        print("Model load error:", e)

class Features(BaseModel):
    src_mac: str
    pkt_count: int
    byte_count: int
    duration: float
    arp_count: int
    packet_in_rate: int

@app.post("/predict")
def predict(f: Features):
    vec = np.array([[f.pkt_count, f.byte_count, f.duration, f.arp_count, f.packet_in_rate]])
    if model is not None:
        score = float(model.predict_proba(vec)[0][1])
        verdict = "attack" if score > 0.5 else "benign"
        return {"verdict": verdict, "score": score}
    score = 0.0
    if f.pkt_count > 2000 or f.packet_in_rate > 500:
        score = 0.95
    elif f.arp_count > 80:
        score = 0.9
    elif f.packet_in_rate > 200:
        score = 0.7
    else:
        score = 0.05
    return {"verdict": "attack" if score > 0.5 else "benign", "score": score}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
