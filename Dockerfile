FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONPATH=/app/src:/app
RUN python tasks.py data --synthetic --limit 600 && python tasks.py train
RUN useradd --create-home detector
USER detector
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "phishdetect.api:app", "--host", "0.0.0.0", "--port", "8000"]
