FROM python:3.8-slim-buster
RUN apt-get update -y
RUN apt-get install -y python3-dev build-essential
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./