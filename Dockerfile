FROM python:3.8-slim-buster
RUN apt-get update -y
RUN apt-get install -y python3-dev build-essential
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY staking_deposit ./staking_deposit
COPY utils ./utils
COPY stateFile.json ./stateFile.json
COPY node_operator.py ./node_operator.py
