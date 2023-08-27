FROM python:alpine

ENV verbosity '5'
ENV logType sys.stdout
ENV logAddress localhost
ENV logPort 514
ENV forwardIp 47.91.242.120
ENV forwardPort 10013
ENV delay 0.0001
ENV bufferSize 4096
ENV listenPort 1898
ENV mqttHost 192.168.188.145
ENV mqttPort 1883
ENV mqttUser enverproxy
ENV mqttPassword enverproxy_pw


WORKDIR /data/app
COPY enverproxy ./

RUN pip3 install paho-mqtt

EXPOSE 1898

CMD ["python3", "./enverproxy.py"]
