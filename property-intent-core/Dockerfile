FROM python:3.12-slim
WORKDIR /srv

# Dependencies live in their own immutable layer. Editing app code must not
# redownload/reinstall the whole Python dependency graph.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN useradd --system --uid 10001 intent && chown -R intent:intent /srv
USER intent
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080"]
