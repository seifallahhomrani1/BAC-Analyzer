FROM python:3-alpine
WORKDIR /app
RUN apk add --no-cache gcc libffi-dev musl-dev
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV FLASK_PORT=50111
EXPOSE 50111
CMD ["python", "app.py"]
