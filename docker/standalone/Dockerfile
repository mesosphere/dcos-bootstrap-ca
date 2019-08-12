FROM busybox:1.31-glibc

ADD dcos-bootstrap-ca /usr/bin/dcos-bootstrap-ca-standalone
ADD init_script /init_script

CMD ["./init_script"]
