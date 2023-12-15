FROM python:3.9-alpine

WORKDIR /app

COPY . /app

RUN apk add --no-cache ca-certificates && \
apk update && apk add --no-cache wireshark libpcap-dev
RUN apk add --no-cache --virtual .build-deps gcc g++ py3-pip git cmake make
RUN git submodule update --init --recursive 
RUN cd PcapPlusPlus && cmake -S . -B build && cd build && make &&\ 
cmake --install . 
RUN pip install -U pip && pip install typer[all] scapy numpy pcap_splitter &&\
pip install torch --index-url https://download.pytorch.org/whl/cpu
RUN apk del .build-deps


ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]