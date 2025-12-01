FROM python:3.10-slim
WORKDIR /detector
RUN apt-get update && apt-get install -y python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install fastapi uvicorn scikit-learn joblib numpy
COPY detector_service.py /detector/
VOLUME ["/models"]
EXPOSE 8000
CMD ["python3","/detector/detector_service.py"]
