FROM python:3.12-slim
WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .
RUN useradd --system --uid 10001 growth && chown -R growth:growth /srv
USER growth
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080"]
