# Nginx sslkeylog module version 0.2.0

This module adds SSL-related variables for logging session key data. Just in case you (or Big Brother) need it.

## Variables
All variables are hex-encoded.
### For any SSL/TLS version
- `$sslkeylog_se` - SSL session id (same as `$ssl_session_id`)
- `$sslkeylog_cs` - cipher suite id (like `$ssl_cipher`, but in hex)
- `$sslkeylog_cr` - client random (32 bytes Random value from the Client Hello message)
### For SSL 3.0 and TLS 1.0, 1.1, 1.2
- `$sslkeylog_sr` - server random
- `$sslkeylog_mk` - master key (e.g session key)
### For TLS 1.3
- `$sslkeylog_cets` - client early traffic secret
- `$sslkeylog_chts` - client handshake traffic secret
- `$sslkeylog_shts` - server handshake traffic secret
- `$sslkeylog_cts` - the first application traffic secret for the client side
- `$sslkeylog_sts` - the first application traffic secret for the server side
- `$sslkeylog_es` - exporter secret (used for 1-RTT keys in older QUIC drafts)
- `$sslkeylog_ees` - early exporter secret (used for 0-RTT keys in older QUIC drafts)

## Prerequisites
- OpenSSL 1.1.1+. Other libssl flavours, like BoringSSL, may work if they provide `SSL_CTX_set_keylog_callback()` function (LibreSSL does not).
- Tested (a little, not in production!) on nginx 1.20, 1.24.
- Since version 0.2.0 it is necessary to patch nginx sources - that's the price of TLSv1.3 support. I've provided patches for versions I've worked with.

## Building
```
<nginx src dir> $ patch -Np1 -i <path/to/sslkeylog/module>/nginx-patches/<nginx-version>.patch
<nginx src dir> $ ./configure <your usual nginx configure options> --add-module=<path/to/sslkeylog/module>
```

## Usage
The following nginx.conf allows you to produce logs in [NSS Key Log Format](https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format):
```
http {
...

  map $sslkeylog_shts $log_shts {
    '' '';
    default 'SERVER_HANDSHAKE_TRAFFIC_SECRET $sslkeylog_cr $sslkeylog_shts\n';
  }

  map $sslkeylog_chts $log_chts {
    '' '';
    default 'CLIENT_HANDSHAKE_TRAFFIC_SECRET $sslkeylog_cr $sslkeylog_chts\n';
  }

  map $sslkeylog_sts $log_sts {
    '' '';
    default 'SERVER_TRAFFIC_SECRET_0 $sslkeylog_cr $sslkeylog_sts\n';
  }

  map $sslkeylog_cts $log_cts {
    '' '';
    default 'CLIENT_TRAFFIC_SECRET_0 $sslkeylog_cr $sslkeylog_cts\n';
  }

  map $sslkeylog_es $log_es {
    '' '';
    default 'EXPORTER_SECRET $sslkeylog_cr $sslkeylog_es\n';
  }

  map $sslkeylog_ees $log_ees {
    '' '';
    default 'EARLY_EXPORTER_SECRET $sslkeylog_cr $sslkeylog_ees\n';
  }

  map $sslkeylog_cets $log_cets {
    '' '';
    default 'CLIENT_EARLY_TRAFFIC_SECRET $sslkeylog_cr $sslkeylog_cets\n';
  }

  map $ssl_protocol $keylog_lines {
    'TLSv1.3' "$log_cets$log_ees$log_shts$log_chts$log_es$log_sts$log_cts";
    '' '';
    default "CLIENT_RANDOM $sslkeylog_cr $sslkeylog_mk\n";
  }

  log_format sslkeylog escape=none '$keylog_lines';

  access_log  /var/log/nginx/sslkeys.log  sslkeylog;
...
}
```
