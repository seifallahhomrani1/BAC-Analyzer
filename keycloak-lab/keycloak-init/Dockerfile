FROM python:3-alpine
RUN apk add --no-cache curl
COPY init-users.py /init-users.py
CMD ["python3", "/init-users.py"]
