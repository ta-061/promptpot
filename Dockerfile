FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY promptpot.py /app/promptpot.py

EXPOSE 11434 1234 8000 7860 8188

ENTRYPOINT ["python", "/app/promptpot.py"]
