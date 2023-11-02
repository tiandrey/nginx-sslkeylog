# Nginx sslkeylog module version 0.1.0

This module adds SSL-related variables for logging session key data. Just in case you (or Big Brother) need it.

## Variables

- $sslkeylog_se - SSL session id (same as $ssl_session_id)
- $sslkeylog_cr - client random
- $sslkeylog_sr - server random
- $sslkeylog_mk - master key (e.g session key)
- $sslkeylog_cs - cipher suite id (like $ssl_cipher, but in hex)

## Prerequisites
- OpenSSL 1.1+. Version 1.0 currently is not (and probably would not be) supported as it has different API.
- Tested on nginx 1.14, 1.18, 1.20.

## Building
`<nginx src dir> $ ./configure <your usual nginx configure options> --add-module=path/to/sslkeylog/module`

## Usage
nginx.conf
```
http {
...
  log_format sslkeylog '$remote_addr [$time_local] $sslkeylog_cs $sslkeylog_se $sslkeylog_cr $sslkeylog_sr $sslkeylog_mk';
  access_log  /var/log/nginx/sslkeys.log  sslkeylog;
...
}
```
