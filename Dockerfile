FROM python:3.14-alpine

LABEL org.opencontainers.image.source="https://github.com/ta-061/promptpot" \
      org.opencontainers.image.description="Multi-profile honeypot for exposed local-LLM services (Ollama, LM Studio, vLLM, Gradio, ComfyUI)" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY promptpot.py /app/promptpot.py
COPY healthcheck.py /app/healthcheck.py

EXPOSE 11434 1234 8000 7860 8188

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "/app/healthcheck.py"]

ENTRYPOINT ["python", "/app/promptpot.py"]