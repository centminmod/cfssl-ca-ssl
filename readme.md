Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server, client and peer self-signed SSL certificates with it. Mainly intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based TLS/SSL client certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives using [gen-client option](#client-ssl-certificate).

Nginx Configuration

```
cp -a /etc/cfssl/centminmod.com-ca.pem /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca.pem
```

```
ssl_client_certificate /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca.pem;
ssl_verify_client on;

if ($ssl_client_verify != SUCCESS) {
    return 403;
}
```

Client connection

```
curl -k --cert /etc/cfssl/clientcerts/client.centminmod.com.pem https://domain.com
```

# Contents


* [Usage](#usage)
* [CA Certificate](#ca-certificate)
* [Server Wildcard SSL Certificate](#server-wildcard-ssl-certificate)
* [Server SSL Certificate](#server-ssl-certificate)
* [Client SSL Certificate](#client-ssl-certificate)
* [Peer Wildcard SSL Certificate](#peer-wildcard-ssl-certificate)
* [Peer SSL Certificate](#peer-wildcard-ssl-certificate)

# Usage

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh

Usage:

Generate CA certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca domain.com expiryhrs

Generate TLS server certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server domain.com expiryhrs server

Generate TLS server wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server domain.com expiryhrs wildcard

Generate TLS Client certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client domain.com expiryhrs client

Generate TLS Peer certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer domain.com expiryhrs peer

Generate TLS Peer wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer domain.com expiryhrs wildcard
```

# CA Certificate

Generate CA certificates for centminmod.com with 87600 hrs expiry = 10yrs

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600             
2020/09/12 11:24:09 [INFO] generating a new CA key and certificate from CSR
2020/09/12 11:24:09 [INFO] generate received request
2020/09/12 11:24:09 [INFO] received CSR
2020/09/12 11:24:09 [INFO] generating key: ecdsa-256
2020/09/12 11:24:09 [INFO] encoded CSR
2020/09/12 11:24:09 [INFO] signed certificate with serial number 427871406414710309376762164705690502841132438546
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4a:f2:6a:dc:cc:15:24:3f:bc:a2:40:19:f5:e9:a5:50:c4:fc:d4:12
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:19:00 2020 GMT
            Not After : Sep 10 11:19:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e8:97:88:3b:c0:dc:46:e5:23:04:d1:e2:de:52:
                    97:e7:a4:e1:a6:12:5a:04:86:f5:e5:b6:7c:ed:57:
                    3c:97:ae:74:63:7e:0a:67:a6:94:eb:77:5b:8f:93:
                    9f:56:ea:1e:56:7d:d4:de:fe:e6:b0:5a:82:fb:35:
                    31:f6:6b:29:95
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:0f:34:0a:9e:94:a8:c6:17:05:b7:ad:b7:e5:78:
         e3:f8:7c:cd:f1:76:5f:69:c9:e3:17:a3:31:b1:9d:8a:4a:79:
         02:21:00:8d:83:1a:ba:ac:85:c0:93:f4:48:fa:b6:df:b3:41:
         e5:e2:26:37:1b:dc:50:8d:32:68:80:15:8f:03:2a:53:98

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca key: /etc/cfssl/centminmod.com-ca-key.pem
ca csr: /etc/cfssl/centminmod.com-ca.csr
ca csr profile: /etc/cfssl/centminmod.com-ca.csr.json
ca profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "427871406414710309376762164705690502841132438546",
  "not_before": "2020-09-12T11:19:00Z",
  "not_after": "2030-09-10T11:19:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB2jCCAYCgAwIBAgIUSvJq3MwVJD+8okAZ9emlUMT81BIwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTE5MDBaFw0z\nMDA5MTAxMTE5MDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAATol4g7wNxG5SME0eLeUpfnpOGmEloEhvXltnzt\nVzyXrnRjfgpnppTrd1uPk59W6h5WfdTe/uawWoL7NTH2aymVo0IwQDAOBgNVHQ8B\nAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUfuOu3ib4hoVjvVhJ\nJRT7l5grNF8wCgYIKoZIzj0EAwIDSAAwRQIgDzQKnpSoxhcFt6235Xjj+HzN8XZf\nacnjF6MxsZ2KSnkCIQCNgxq6rIXAk/RI+rbfs0Hl4iY3G9xQjTJogBWPAypTmA==\n-----END CERTIFICATE-----\n"
}
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard
2020/09/12 11:25:25 [INFO] generate received request
2020/09/12 11:25:25 [INFO] received CSR
2020/09/12 11:25:25 [INFO] generating key: ecdsa-256
2020/09/12 11:25:25 [INFO] encoded CSR
2020/09/12 11:25:25 [INFO] signed certificate with serial number 643893016033135791192125429617958731885395959998
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            70:c9:29:53:33:c2:ad:83:17:56:49:73:4e:98:20:fd:d7:01:e0:be
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:20:00 2020 GMT
            Not After : Sep 10 11:20:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:4b:a2:14:51:4a:ab:7d:ce:c3:5e:a1:dc:c2:3f:
                    52:50:95:fe:c0:e1:ec:5e:af:fa:c9:e7:51:1b:4c:
                    8e:04:60:47:40:b5:2b:65:48:67:29:e3:85:90:73:
                    ad:0f:5c:30:06:b5:12:e4:c7:60:24:9f:1c:f9:46:
                    94:a3:9e:1c:6b
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                88:DA:62:70:47:16:32:A9:3D:6A:62:03:07:C4:AB:3B:5E:3B:C6:F5
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:31:c8:02:9b:95:e7:e7:44:88:e1:71:a0:02:7e:
         8f:ec:d6:52:42:d7:48:76:b3:1f:e0:ab:7a:68:aa:a5:72:81:
         02:20:23:b9:e4:7b:bb:03:36:3e:c0:14:5e:10:65:02:81:1c:
         2b:b6:32:32:b8:f5:07:8e:d6:1c:63:7c:20:59:eb:76

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server key: /etc/cfssl/servercerts/centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/centminmod.com-key.pem;

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "643893016033135791192125429617958731885395959998",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T11:20:00Z",
  "not_after": "2030-09-10T11:20:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "88:DA:62:70:47:16:32:A9:3D:6A:62:03:07:C4:AB:3B:5E:3B:C6:F5",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICGTCCAcCgAwIBAgIUcMkpUzPCrYMXVklzTpgg/dcB4L4wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTIwMDBaFw0z\nMDA5MTAxMTIwMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARLohRRSqt9zsNeodzCP1JQlf7A4exer/rJ51Eb\nTI4EYEdAtStlSGcp44WQc60PXDAGtRLkx2Aknxz5RpSjnhxro4GBMH8wDgYDVR0P\nAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYD\nVR0OBBYEFIjaYnBHFjKpPWpiAwfEqzteO8b1MCsGA1UdEQQkMCKCDmNlbnRtaW5t\nb2QuY29tghAqLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0cAMEQCIDHIApuV\n5+dEiOFxoAJ+j+zWUkLXSHazH+CremiqpXKBAiAjueR7uwM2PsAUXhBlAoEcK7Yy\nMrj1B47WHGN8IFnrdg==\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600
2020/09/12 11:26:07 [INFO] generate received request
2020/09/12 11:26:07 [INFO] received CSR
2020/09/12 11:26:07 [INFO] generating key: ecdsa-256
2020/09/12 11:26:07 [INFO] encoded CSR
2020/09/12 11:26:07 [INFO] signed certificate with serial number 355851856854210141265300821511927833347403647723
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3e:54:f2:fa:a7:84:5a:e7:0f:1b:2e:3a:d9:da:94:cf:a6:7d:8a:eb
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:21:00 2020 GMT
            Not After : Sep 10 11:21:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:90:b3:25:46:01:67:79:cb:1d:c5:2c:c6:45:5c:
                    0d:84:e1:77:3c:c7:dc:4e:de:9f:c7:70:7f:66:dc:
                    98:47:2e:ec:b1:71:5a:2b:75:74:d2:bd:a7:f3:3f:
                    ec:de:2b:01:29:d6:a6:b0:dd:37:62:59:ed:e1:05:
                    6d:6c:f3:2e:3a
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                C0:47:64:A5:7F:7E:80:16:61:9B:00:EE:03:88:A0:FA:DE:DD:4F:28
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:6e:e9:88:83:a0:3c:f4:c3:3b:98:b6:c8:4e:79:
         84:03:b7:1c:23:64:c3:46:d7:ed:5b:51:e7:3f:b8:e7:d9:1c:
         02:21:00:c3:2e:1b:bd:97:37:74:68:85:a0:3f:78:6c:9e:39:
         e4:8a:b5:fd:76:99:05:93:29:67:c7:e0:81:58:84:9d:8d

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server key: /etc/cfssl/servercerts/centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/centminmod.com-key.pem;

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "355851856854210141265300821511927833347403647723",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T11:21:00Z",
  "not_after": "2030-09-10T11:21:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "C0:47:64:A5:7F:7E:80:16:61:9B:00:EE:03:88:A0:FA:DE:DD:4F:28",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUPlTy+qeEWucPGy462dqUz6Z9iuswCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTIxMDBaFw0z\nMDA5MTAxMTIxMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASQsyVGAWd5yx3FLMZFXA2E4Xc8x9xO3p/HcH9m\n3JhHLuyxcVordXTSvafzP+zeKwEp1qaw3TdiWe3hBW1s8y46o28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUwEdkpX9+gBZhmwDuA4ig+t7dTygwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIgbumIg6A89MM7mLbITnmEA7ccI2TDRtft\nW1HnP7jn2RwCIQDDLhu9lzd0aIWgP3hsnjnkirX9dpkFkylnx+CBWISdjQ==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server
2020/09/12 11:26:42 [INFO] generate received request
2020/09/12 11:26:42 [INFO] received CSR
2020/09/12 11:26:42 [INFO] generating key: ecdsa-256
2020/09/12 11:26:42 [INFO] encoded CSR
2020/09/12 11:26:42 [INFO] signed certificate with serial number 518456004323665490076061413231222364632137454220
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5a:d0:5f:0c:94:b6:8f:0f:5f:6a:24:e3:c5:a6:e5:05:5d:85:d2:8c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:22:00 2020 GMT
            Not After : Sep 10 11:22:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:54:45:ba:af:54:d6:07:f6:3f:10:b3:43:f4:ed:
                    30:27:66:83:e6:fc:ca:5e:b9:72:04:c6:56:66:1b:
                    29:c0:df:ae:a5:01:ff:0b:af:55:35:26:88:3b:19:
                    f8:2a:ac:40:10:50:85:f4:22:c8:0d:17:77:47:6b:
                    6c:77:ea:a1:25
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                12:E5:D8:B9:AF:12:AF:52:A3:68:D8:B5:B8:39:51:F6:4E:18:E8:64
            X509v3 Authority Key Identifier: 
                keyid:7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:16:9c:78:5a:1b:af:81:69:c9:c9:a7:76:66:c3:
         54:7a:0b:88:cd:ba:8c:a0:17:ac:02:19:82:38:18:9c:0f:2e:
         02:21:00:f9:86:bd:05:5f:4d:66:30:94:1e:ad:fd:a0:70:b3:
         b1:bd:63:77:48:eb:14:86:07:05:cf:9c:18:11:a8:41:de

server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
server key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/server.centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/server.centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/server.centminmod.com-key.pem;

{
  "subject": {
    "common_name": "server.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "server.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "518456004323665490076061413231222364632137454220",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T11:22:00Z",
  "not_after": "2030-09-10T11:22:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F",
  "subject_key_id": "12:E5:D8:B9:AF:12:AF:52:A3:68:D8:B5:B8:39:51:F6:4E:18:E8:64",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICODCCAd6gAwIBAgIUWtBfDJS2jw9faiTjxablBV2F0owwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTIyMDBaFw0z\nMDA5MTAxMTIyMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVEW6r1TWB/Y/ELND9O0wJ2aD5vzK\nXrlyBMZWZhspwN+upQH/C69VNSaIOxn4KqxAEFCF9CLIDRd3R2tsd+qhJaOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUEuXYua8Sr1KjaNi1uDlR9k4Y6GQwHwYDVR0jBBgwFoAU\nfuOu3ib4hoVjvVhJJRT7l5grNF8wIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0gAMEUCIBaceFobr4FpycmndmbDVHoLiM26jKAX\nrAIZgjgYnA8uAiEA+Ya9BV9NZjCUHq39oHCzsb1jd0jrFIYHBc+cGBGoQd4=\n-----END CERTIFICATE-----\n"
}

```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600
2020/09/12 11:27:16 [INFO] generate received request
2020/09/12 11:27:16 [INFO] received CSR
2020/09/12 11:27:16 [INFO] generating key: ecdsa-256
2020/09/12 11:27:16 [INFO] encoded CSR
2020/09/12 11:27:16 [INFO] signed certificate with serial number 510718541091169151831828772721541812450962802420
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            59:75:69:53:c8:3c:90:37:22:94:51:b6:20:05:94:7b:11:a9:86:f4
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:22:00 2020 GMT
            Not After : Sep 10 11:22:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:5e:be:ec:12:95:8a:e6:fb:06:f2:84:87:31:8d:
                    33:26:07:a5:03:a1:61:3f:b9:a5:76:41:12:34:f8:
                    18:ac:8c:d3:78:f5:cc:4d:5d:77:dd:20:ee:f9:b0:
                    c6:eb:53:d7:34:f5:16:2f:0b:f6:75:8b:b7:f5:6f:
                    94:9b:ff:56:b0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                27:38:62:64:AB:E7:C7:48:D3:DE:98:26:33:45:89:09:B2:11:52:8E
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:ff:db:2a:bd:76:58:43:a2:4c:5d:5e:79:86:
         db:bb:5a:03:26:4f:3b:16:cf:bb:d3:22:76:b6:e2:59:3a:48:
         70:02:20:03:5e:eb:01:f2:de:d8:1e:e7:75:db:38:fa:40:f6:
         5d:4a:94:e7:7e:0f:99:80:26:02:3a:2c:a1:a9:2b:13:95

client cert: /etc/cfssl/clientcerts/centminmod.com.pem
client key: /etc/cfssl/clientcerts/centminmod.com-key.pem
client csr: /etc/cfssl/clientcerts/centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "510718541091169151831828772721541812450962802420",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T11:22:00Z",
  "not_after": "2030-09-10T11:22:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "27:38:62:64:AB:E7:C7:48:D3:DE:98:26:33:45:89:09:B2:11:52:8E",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUWXVpU8g8kDcilFG2IAWUexGphvQwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTIyMDBaFw0z\nMDA5MTAxMTIyMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARevuwSlYrm+wbyhIcxjTMmB6UDoWE/uaV2QRI0\n+BisjNN49cxNXXfdIO75sMbrU9c09RYvC/Z1i7f1b5Sb/1awo28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUJzhiZKvnx0jT3pgmM0WJCbIRUo4wGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAP/bKr12WEOiTF1eeYbbu1oDJk87Fs+7\n0yJ2tuJZOkhwAiADXusB8t7YHud12zj6QPZdSpTnfg+ZgCYCOiyhqSsTlQ==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client
2020/09/12 11:27:39 [INFO] generate received request
2020/09/12 11:27:39 [INFO] received CSR
2020/09/12 11:27:39 [INFO] generating key: ecdsa-256
2020/09/12 11:27:39 [INFO] encoded CSR
2020/09/12 11:27:39 [INFO] signed certificate with serial number 480680860407487031356125533623210121082093482064
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            54:32:79:a9:e4:bc:04:91:de:bb:d5:77:b8:f1:68:bd:a6:7c:b0:50
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:23:00 2020 GMT
            Not After : Sep 10 11:23:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:74:5c:b4:39:4b:93:ba:9c:31:03:f8:9c:92:42:
                    10:65:96:0e:9b:65:aa:67:ca:84:b1:25:d9:23:20:
                    38:b0:49:b0:dc:dd:c5:18:92:fc:df:df:d3:aa:92:
                    30:95:85:11:88:9f:bb:61:91:8b:d4:3f:f6:3d:19:
                    94:65:8a:79:75
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                7B:56:47:1E:CB:CD:2E:50:74:C2:C4:63:9F:52:E6:EB:95:4D:A2:C6
            X509v3 Authority Key Identifier: 
                keyid:7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:3e:bc:3c:35:09:72:9c:67:b4:ff:08:de:31:1d:
         51:ca:a3:92:86:5f:a0:c4:08:fb:76:6e:bb:c5:e1:28:b0:3e:
         02:21:00:92:d4:48:6d:89:4a:00:65:c6:90:84:40:30:37:6a:
         56:82:7c:9d:da:da:bc:8e:20:b1:47:38:22:a7:ec:c7:5a

client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
client key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

{
  "subject": {
    "common_name": "client.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "client.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "480680860407487031356125533623210121082093482064",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-12T11:23:00Z",
  "not_after": "2030-09-10T11:23:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F",
  "subject_key_id": "7B:56:47:1E:CB:CD:2E:50:74:C2:C4:63:9F:52:E6:EB:95:4D:A2:C6",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICODCCAd6gAwIBAgIUVDJ5qeS8BJHeu9V3uPFovaZ8sFAwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTIzMDBaFw0z\nMDA5MTAxMTIzMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdFy0OUuTupwxA/ickkIQZZYOm2Wq\nZ8qEsSXZIyA4sEmw3N3FGJL839/TqpIwlYURiJ+7YZGL1D/2PRmUZYp5daOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUe1ZHHsvNLlB0wsRjn1Lm65VNosYwHwYDVR0jBBgwFoAU\nfuOu3ib4hoVjvVhJJRT7l5grNF8wIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0gAMEUCID68PDUJcpxntP8I3jEdUcqjkoZfoMQI\n+3Zuu8XhKLA+AiEAktRIbYlKAGXGkIRAMDdqVoJ8ndravI4gsUc4Iqfsx1o=\n-----END CERTIFICATE-----\n"
}
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard
2020/09/12 11:38:18 [INFO] generate received request
2020/09/12 11:38:18 [INFO] received CSR
2020/09/12 11:38:18 [INFO] generating key: ecdsa-256
2020/09/12 11:38:18 [INFO] encoded CSR
2020/09/12 11:38:18 [INFO] signed certificate with serial number 417857750383195807981289036429602876449452266039
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            49:31:63:ba:8e:90:60:db:19:cd:69:6c:5f:78:d3:78:1f:21:12:37
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:33:00 2020 GMT
            Not After : Sep 10 11:33:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:b9:2a:a6:aa:c6:75:91:d9:2a:79:a2:30:44:a1:
                    2c:f8:92:1a:cf:3f:6b:a5:6b:f0:34:c5:a7:12:59:
                    db:51:12:4b:e4:9f:fb:3d:60:c2:db:60:d5:83:3c:
                    bf:79:58:82:57:03:67:3c:61:b7:fb:fd:9e:77:19:
                    5a:b7:ee:92:3e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                1B:46:8F:8E:74:6B:6E:D1:37:BB:E4:E6:52:CA:5C:8A:3C:37:5D:32
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:6e:2e:f4:56:e3:a3:0e:aa:7e:19:f7:0e:8e:33:
         fd:81:55:fc:d3:15:39:46:8d:e2:25:5c:77:9b:da:76:36:7b:
         02:21:00:be:6f:a5:ac:00:43:e1:46:65:f2:d5:7c:c7:98:52:
         13:2d:32:09:bf:3b:f4:b8:e9:c5:24:1e:c3:b3:cb:ca:86

peer cert: /etc/cfssl/peercerts/centminmod.com.pem
peer key: /etc/cfssl/peercerts/centminmod.com-key.pem
peer csr: /etc/cfssl/peercerts/centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "417857750383195807981289036429602876449452266039",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T11:33:00Z",
  "not_after": "2030-09-10T11:33:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "1B:46:8F:8E:74:6B:6E:D1:37:BB:E4:E6:52:CA:5C:8A:3C:37:5D:32",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICJTCCAcugAwIBAgIUSTFjuo6QYNsZzWlsX3jTeB8hEjcwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTMzMDBaFw0z\nMDA5MTAxMTMzMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAS5KqaqxnWR2Sp5ojBEoSz4khrPP2ula/A0xacS\nWdtREkvkn/s9YMLbYNWDPL95WIJXA2c8Ybf7/Z53GVq37pI+o4GMMIGJMA4GA1Ud\nDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDAYDVR0T\nAQH/BAIwADAdBgNVHQ4EFgQUG0aPjnRrbtE3u+TmUspcijw3XTIwKwYDVR0RBCQw\nIoIOY2VudG1pbm1vZC5jb22CECouY2VudG1pbm1vZC5jb20wCgYIKoZIzj0EAwID\nSAAwRQIgbi70VuOjDqp+GfcOjjP9gVX80xU5Ro3iJVx3m9p2NnsCIQC+b6WsAEPh\nRmXy1XzHmFITLTIJvzv0uOnFJB7Ds8vKhg==\n-----END CERTIFICATE-----\n"
}

```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer
2020/09/12 11:35:41 [INFO] generate received request
2020/09/12 11:35:41 [INFO] received CSR
2020/09/12 11:35:41 [INFO] generating key: ecdsa-256
2020/09/12 11:35:41 [INFO] encoded CSR
2020/09/12 11:35:41 [INFO] signed certificate with serial number 318535675488440494537446464360803320408370491724
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            37:cb:a2:39:ae:18:47:e4:98:61:70:b3:cf:07:f9:e7:4a:5e:b1:4c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 11:31:00 2020 GMT
            Not After : Sep 10 11:31:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:16:20:4c:98:ba:fb:70:0e:f4:d2:54:45:3c:9c:
                    09:2a:c7:94:49:6d:2a:47:ca:e1:f3:75:11:7d:53:
                    30:47:72:fe:2d:ce:a7:c2:85:55:30:85:09:87:ca:
                    b0:4f:b5:58:44:6b:61:56:eb:57:22:13:a5:bc:de:
                    a5:e9:ab:70:52
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                BA:70:A6:09:91:C2:E4:DC:73:6D:CC:CA:AE:69:98:32:6B:2A:E3:F2
            X509v3 Authority Key Identifier: 
                keyid:7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:76:d9:47:91:e0:f0:a2:67:68:1b:92:2f:63:34:
         84:5b:36:0c:b4:c0:cf:16:cf:41:ee:7c:7a:78:66:15:f9:f8:
         02:21:00:83:de:bb:3b:db:24:f7:f4:a1:6e:38:22:13:b9:c6:
         e0:dd:df:91:a0:5d:a2:80:33:61:f6:67:9c:8f:6e:6c:aa

peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
peer key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

{
  "subject": {
    "common_name": "peer.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "peer.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "serial_number": "318535675488440494537446464360803320408370491724",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-12T11:31:00Z",
  "not_after": "2030-09-10T11:31:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "7E:E3:AE:DE:26:F8:86:85:63:BD:58:49:25:14:FB:97:98:2B:34:5F",
  "subject_key_id": "BA:70:A6:09:91:C2:E4:DC:73:6D:CC:CA:AE:69:98:32:6B:2A:E3:F2",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICPjCCAeSgAwIBAgIUN8uiOa4YR+SYYXCzzwf550pesUwwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMTMxMDBaFw0z\nMDA5MTAxMTMxMDBaMFAxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEcMBoGA1UEAxMTcGVlci5jZW50bWlubW9kLmNvbTBZ\nMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBYgTJi6+3AO9NJURTycCSrHlEltKkfK\n4fN1EX1TMEdy/i3Op8KFVTCFCYfKsE+1WERrYVbrVyITpbzepemrcFKjgaAwgZ0w\nDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAM\nBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS6cKYJkcLk3HNtzMquaZgyayrj8jAfBgNV\nHSMEGDAWgBR+467eJviGhWO9WEklFPuXmCs0XzAeBgNVHREEFzAVghNwZWVyLmNl\nbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0gAMEUCIHbZR5Hg8KJnaBuSL2M0hFs2\nDLTAzxbPQe58enhmFfn4AiEAg967O9sk9/ShbjgiE7nG4N3fkaBdooAzYfZnnI9u\nbKo=\n-----END CERTIFICATE-----\n"
}

```