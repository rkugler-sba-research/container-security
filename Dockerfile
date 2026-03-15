FROM alpine

RUN echo "pass=abcde" > /etc/myconfig

RUN rm /etc/myconfig
