FROM python:3.12-slim AS base

LABEL maintainer="MedSBOM Contributors"
LABEL description="MedSBOM — Open-source FDA/IEC-62304 compliance layer for medical device SBOMs"
LABEL license="Apache-2.0"

WORKDIR /app

# Install system deps for WeasyPrint PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev libcairo2 && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY medsbom/ ./medsbom/

RUN pip install --no-cache-dir .

# Non-root user for security
RUN useradd --create-home medsbom
USER medsbom

# CLI entrypoint by default
ENTRYPOINT ["medsbom"]
CMD ["--help"]

# API mode: docker run medsbom-api --api
FROM base AS api
EXPOSE 8000
CMD ["uvicorn", "medsbom.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
