FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd --system --uid 10001 growth && chown -R growth:growth /srv
USER growth
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080"]
