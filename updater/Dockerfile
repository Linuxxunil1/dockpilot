FROM python:3.12-slim
RUN pip install --no-cache-dir docker==7.1.0
WORKDIR /app
COPY updater.py .
CMD ["python", "-u", "updater.py"]
