## nginx-udp

### Requirements

* tengine 2.2.0

### Installation

```
git clone https://github.com/eleme/nginx-udp
dso_tool --add-module=`pwd`/nginx-udp
```

### Configuration

```
dso {
    load ngx_http_udp_module.so;
}

udp_server localhost:8086;
udp_format 'nginx.requests,hostname=$hostname,host=$host,upstream=$upstream_addr,status_code=$status response_time=$request_time,response_size=$body_bytes_sent ${udp_usec}000';
```
