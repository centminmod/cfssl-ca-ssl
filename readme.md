Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server and client self-signed SSL certificates with it. Intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based TLS/SSL client certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives.

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
* [Server SSL Certificate](#server-ssl-certificate)
* [Client SSL Certificate](#client-ssl-certificate)

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
```

# CA Certificate

Generate CA certificates for centminmod.com with 87600 hrs expiry = 10yrs

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600             
2020/09/12 08:25:40 [INFO] generating a new CA key and certificate from CSR
2020/09/12 08:25:40 [INFO] generate received request
2020/09/12 08:25:40 [INFO] received CSR
2020/09/12 08:25:40 [INFO] generating key: ecdsa-256
2020/09/12 08:25:40 [INFO] encoded CSR
2020/09/12 08:25:40 [INFO] signed certificate with serial number 140358779814626189945165606296894275786403021566
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            18:95:e7:c5:e6:a8:54:7c:4e:15:10:ff:b3:33:c3:f7:eb:29:02:fe
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 08:21:00 2020 GMT
            Not After : Sep 10 08:21:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:7a:37:90:7a:31:6a:7a:97:c9:f3:25:72:f5:3f:
                    4d:44:26:d7:d0:7e:56:56:f2:3e:af:00:cf:49:e1:
                    fa:41:2a:ac:15:91:9a:f5:11:7f:fa:6e:0b:11:18:
                    d2:d0:7a:e9:50:47:ff:6e:a0:bd:ac:4b:bd:1f:83:
                    1d:97:77:ee:fe
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:fe:08:bb:51:af:ee:5c:2a:6a:a7:17:9b:8b:
         2c:fe:58:1f:e1:5f:41:f8:71:ea:15:26:f2:9d:3f:c5:e2:e4:
         2c:02:21:00:ef:69:af:a5:93:4a:4f:81:a1:85:f0:a6:f3:7c:
         19:58:41:8f:68:b3:1a:57:31:d2:9e:ad:6b:9b:6c:13:71:bf

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
  "serial_number": "140358779814626189945165606296894275786403021566",
  "not_before": "2020-09-12T08:21:00Z",
  "not_after": "2030-09-10T08:21:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB2zCCAYCgAwIBAgIUGJXnxeaoVHxOFRD/szPD9+spAv4wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIwODIxMDBaFw0z\nMDA5MTAwODIxMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAR6N5B6MWp6l8nzJXL1P01EJtfQflZW8j6vAM9J\n4fpBKqwVkZr1EX/6bgsRGNLQeulQR/9uoL2sS70fgx2Xd+7+o0IwQDAOBgNVHQ8B\nAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIgNAcaxY+eaPtSWa\n/uwkTid5jxYwCgYIKoZIzj0EAwIDSQAwRgIhAP4Iu1Gv7lwqaqcXm4ss/lgf4V9B\n+HHqFSbynT/F4uQsAiEA72mvpZNKT4GhhfCm83wZWEGPaLMaVzHSnq1rm2wTcb8=\n-----END CERTIFICATE-----\n"
}
```

# Server Wildcard SSL Certificate

Generate elf-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard
2020/09/12 10:10:02 [INFO] generate received request
2020/09/12 10:10:02 [INFO] received CSR
2020/09/12 10:10:02 [INFO] generating key: ecdsa-256
2020/09/12 10:10:02 [INFO] encoded CSR
2020/09/12 10:10:02 [INFO] signed certificate with serial number 707057410878216591550976083520281169297275481838
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:d9:8d:04:7c:66:aa:41:ad:7c:d1:88:7f:ff:f0:f9:a6:d9:ee:ee
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 10:05:00 2020 GMT
            Not After : Sep 10 10:05:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:79:2d:20:a3:b6:72:de:e2:53:8c:35:36:a5:e1:
                    34:55:3c:c7:b0:bc:72:68:1f:ca:2a:66:49:dc:2c:
                    58:05:4d:47:36:15:92:90:af:08:ea:c1:d5:72:37:
                    4f:2e:b3:1a:cd:24:c8:de:90:b4:07:6b:38:dc:e8:
                    67:43:c4:fe:93
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
                F9:21:EE:83:D3:B1:0E:77:08:DD:55:FA:B4:AD:4E:13:50:98:4F:3E
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:58:9b:5d:0f:8c:6a:37:fc:8a:42:8e:96:a6:48:
         19:cb:f9:8f:b3:a6:04:74:9f:a2:4d:86:1d:d8:cc:d6:31:66:
         02:20:2d:15:fa:a1:4b:70:9e:1b:c3:2b:1a:ab:d9:b2:7c:d6:
         ed:83:e9:5d:80:bc:6c:e2:3b:28:a8:af:a3:a9:92:a8

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
  "serial_number": "707057410878216591550976083520281169297275481838",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T10:05:00Z",
  "not_after": "2030-09-10T10:05:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "F9:21:EE:83:D3:B1:0E:77:08:DD:55:FA:B4:AD:4E:13:50:98:4F:3E",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICGTCCAcCgAwIBAgIUe9mNBHxmqkGtfNGIf//w+abZ7u4wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMDA1MDBaFw0z\nMDA5MTAxMDA1MDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAR5LSCjtnLe4lOMNTal4TRVPMewvHJoH8oqZknc\nLFgFTUc2FZKQrwjqwdVyN08usxrNJMjekLQHazjc6GdDxP6To4GBMH8wDgYDVR0P\nAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYD\nVR0OBBYEFPkh7oPTsQ53CN1V+rStThNQmE8+MCsGA1UdEQQkMCKCDmNlbnRtaW5t\nb2QuY29tghAqLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0cAMEQCIFibXQ+M\najf8ikKOlqZIGcv5j7OmBHSfok2GHdjM1jFmAiAtFfqhS3CeG8MrGqvZsnzW7YPp\nXYC8bOI7KKivo6mSqA==\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600
2020/09/12 10:08:30 [INFO] generate received request
2020/09/12 10:08:30 [INFO] received CSR
2020/09/12 10:08:30 [INFO] generating key: ecdsa-256
2020/09/12 10:08:30 [INFO] encoded CSR
2020/09/12 10:08:30 [INFO] signed certificate with serial number 160511611350106316937477441260979258710917036411
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1c:1d:96:ee:f5:65:96:60:a1:fd:10:a4:de:ee:8b:4b:9f:9a:b9:7b
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 10:04:00 2020 GMT
            Not After : Sep 10 10:04:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:42:61:1c:e9:4d:d1:03:b7:ab:8f:44:3c:59:f4:
                    5b:9a:da:cd:cd:ff:56:10:bb:9b:40:55:38:41:c2:
                    8a:47:c0:52:bf:7d:a4:cf:a1:be:af:e6:73:39:69:
                    16:e6:4c:d0:9b:8c:1c:70:51:20:17:82:83:03:36:
                    11:15:d4:18:c2
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
                7A:62:36:AE:C5:3A:D6:E3:B3:D5:4C:9D:0D:D3:6E:8B:BC:CE:5D:25
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:f6:5f:f1:1c:ec:ee:3a:4b:ac:6b:a4:e8:6c:
         2b:1c:eb:7e:b7:10:21:72:ef:8c:75:54:f4:b1:e5:13:22:a6:
         89:02:20:47:fe:c7:18:1a:37:c9:ee:21:2c:de:2d:e4:51:3d:
         06:d3:b1:b1:dd:42:13:3c:29:6e:f9:4f:69:91:28:af:02

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
  "serial_number": "160511611350106316937477441260979258710917036411",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T10:04:00Z",
  "not_after": "2030-09-10T10:04:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "7A:62:36:AE:C5:3A:D6:E3:B3:D5:4C:9D:0D:D3:6E:8B:BC:CE:5D:25",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUHB2W7vVllmCh/RCk3u6LS5+auXswCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMDA0MDBaFw0z\nMDA5MTAxMDA0MDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARCYRzpTdEDt6uPRDxZ9Fua2s3N/1YQu5tAVThB\nwopHwFK/faTPob6v5nM5aRbmTNCbjBxwUSAXgoMDNhEV1BjCo28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUemI2rsU61uOz1UydDdNui7zOXSUwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAPZf8Rzs7jpLrGuk6GwrHOt+txAhcu+M\ndVT0seUTIqaJAiBH/scYGjfJ7iEs3i3kUT0G07Gx3UITPClu+U9pkSivAg==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server
2020/09/12 10:09:25 [INFO] generate received request
2020/09/12 10:09:25 [INFO] received CSR
2020/09/12 10:09:25 [INFO] generating key: ecdsa-256
2020/09/12 10:09:26 [INFO] encoded CSR
2020/09/12 10:09:26 [INFO] signed certificate with serial number 368976655217868955800593251894877129497334582081
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            40:a1:7c:46:7c:19:dd:95:e6:5f:2c:26:1a:ea:a6:a0:f5:bd:0b:41
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 10:04:00 2020 GMT
            Not After : Sep 10 10:04:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:a3:08:42:aa:c7:d4:71:6d:0c:92:40:18:52:e6:
                    fd:d9:6b:95:31:6e:12:d1:74:9c:ac:21:b9:d9:69:
                    23:62:0e:da:55:dc:2c:8c:db:58:ba:83:73:6b:2b:
                    7c:53:2f:ef:95:e7:75:21:25:40:94:3b:13:6e:84:
                    65:24:b6:44:f5
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
                03:C6:8F:DF:75:8D:D3:A3:46:66:D5:D8:79:59:C0:4E:46:40:08:FE
            X509v3 Authority Key Identifier: 
                keyid:22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:be:e2:31:fb:82:99:5d:25:d6:61:da:a6:0c:
         92:6e:e3:95:39:14:59:d5:d6:a1:56:39:48:da:aa:3c:69:61:
         dc:02:21:00:ae:74:6a:51:cb:02:41:f0:53:fa:69:74:fb:e5:
         37:a2:e0:0e:d9:61:94:4b:30:ca:bf:a5:6b:7c:48:d2:8b:c2

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
  "serial_number": "368976655217868955800593251894877129497334582081",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T10:04:00Z",
  "not_after": "2030-09-10T10:04:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16",
  "subject_key_id": "03:C6:8F:DF:75:8D:D3:A3:46:66:D5:D8:79:59:C0:4E:46:40:08:FE",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICOTCCAd6gAwIBAgIUQKF8RnwZ3ZXmXywmGuqmoPW9C0EwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMDA0MDBaFw0z\nMDA5MTAxMDA0MDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowhCqsfUcW0MkkAYUub92WuVMW4S\n0XScrCG52WkjYg7aVdwsjNtYuoNzayt8Uy/vled1ISVAlDsTboRlJLZE9aOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUA8aP33WN06NGZtXYeVnATkZACP4wHwYDVR0jBBgwFoAU\nIgNAcaxY+eaPtSWa/uwkTid5jxYwIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQC+4jH7gpldJdZh2qYMkm7jlTkUWdXW\noVY5SNqqPGlh3AIhAK50alHLAkHwU/ppdPvlN6LgDtlhlEswyr+la3xI0ovC\n-----END CERTIFICATE-----\n"
}
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600
2020/09/12 08:27:43 [INFO] generate received request
2020/09/12 08:27:43 [INFO] received CSR
2020/09/12 08:27:43 [INFO] generating key: ecdsa-256
2020/09/12 08:27:43 [INFO] encoded CSR
2020/09/12 08:27:43 [INFO] signed certificate with serial number 678089470588275176940890459177912015004629075129
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            76:c6:95:5f:12:4c:b3:89:89:50:59:6b:66:76:df:1d:0b:c2:04:b9
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 08:23:00 2020 GMT
            Not After : Sep 10 08:23:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:7d:93:da:05:1c:03:03:3c:50:75:4b:68:3c:c6:
                    05:1f:ad:0c:ec:b2:da:1b:ab:44:fe:c5:11:ca:70:
                    58:4b:72:85:ea:83:b3:a8:b9:f5:1f:c2:b7:fd:ca:
                    ca:7a:16:de:27:27:1a:7b:7a:32:71:29:95:e5:13:
                    fc:47:a4:d1:85
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
                44:CF:31:3A:AF:70:A4:99:44:4D:83:37:C9:31:66:35:8A:B0:F6:56
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:b9:1d:de:06:98:22:a6:45:c9:82:8a:2d:51:
         96:da:a7:e8:ee:bb:b4:47:e2:6e:f0:d3:3a:c4:97:1c:27:fd:
         a4:02:20:66:27:87:0f:bd:af:6d:95:52:7a:f4:81:42:3f:4b:
         bb:2f:11:41:c0:cd:46:92:5a:85:ac:ea:2e:c3:b9:ad:e1

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
  "serial_number": "678089470588275176940890459177912015004629075129",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T08:23:00Z",
  "not_after": "2030-09-10T08:23:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "44:CF:31:3A:AF:70:A4:99:44:4D:83:37:C9:31:66:35:8A:B0:F6:56",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUdsaVXxJMs4mJUFlrZnbfHQvCBLkwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIwODIzMDBaFw0z\nMDA5MTAwODIzMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAR9k9oFHAMDPFB1S2g8xgUfrQzsstobq0T+xRHK\ncFhLcoXqg7OoufUfwrf9ysp6Ft4nJxp7ejJxKZXlE/xHpNGFo28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQURM8xOq9wpJlETYM3yTFmNYqw9lYwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhALkd3gaYIqZFyYKKLVGW2qfo7ru0R+Ju\n8NM6xJccJ/2kAiBmJ4cPva9tlVJ69IFCP0u7LxFBwM1GklqFrOouw7mt4Q==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client
2020/09/12 08:28:20 [INFO] generate received request
2020/09/12 08:28:20 [INFO] received CSR
2020/09/12 08:28:20 [INFO] generating key: ecdsa-256
2020/09/12 08:28:20 [INFO] encoded CSR
2020/09/12 08:28:20 [INFO] signed certificate with serial number 536066015488322740570861888261035649866467379490
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5d:e6:08:10:2f:93:40:bf:63:5a:73:6e:11:e7:c1:6b:4c:08:09:22
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 08:23:00 2020 GMT
            Not After : Sep 10 08:23:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:26:21:04:0e:6e:3e:b2:bb:53:76:89:4c:7f:d7:
                    f9:fa:bf:2f:03:14:1b:2c:65:75:4b:77:60:e7:44:
                    99:9d:10:2b:91:91:36:ee:d6:b0:a7:c8:d7:57:73:
                    b7:39:8f:45:77:79:af:28:b2:ca:c0:68:58:94:df:
                    a6:4e:8e:e4:51
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
                C7:33:47:63:C1:7E:8F:FB:75:EE:9D:87:D4:F1:D8:AE:EE:DA:FA:09
            X509v3 Authority Key Identifier: 
                keyid:22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:db:45:67:2f:d8:f0:20:43:1f:25:bc:fd:08:
         25:27:a6:75:40:25:1f:b2:ba:1d:32:ec:4a:9b:c7:1a:d8:b6:
         a2:02:21:00:9c:ee:ff:fe:be:4d:e3:d1:8d:d3:4b:e2:78:6c:
         4e:1b:6d:9c:e9:3d:fa:51:74:43:85:2d:75:7a:24:55:93:8e

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
  "serial_number": "536066015488322740570861888261035649866467379490",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-12T08:23:00Z",
  "not_after": "2030-09-10T08:23:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16",
  "subject_key_id": "C7:33:47:63:C1:7E:8F:FB:75:EE:9D:87:D4:F1:D8:AE:EE:DA:FA:09",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICOTCCAd6gAwIBAgIUXeYIEC+TQL9jWnNuEefBa0wICSIwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIwODIzMDBaFw0z\nMDA5MTAwODIzMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJiEEDm4+srtTdolMf9f5+r8vAxQb\nLGV1S3dg50SZnRArkZE27tawp8jXV3O3OY9Fd3mvKLLKwGhYlN+mTo7kUaOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUxzNHY8F+j/t17p2H1PHYru7a+gkwHwYDVR0jBBgwFoAU\nIgNAcaxY+eaPtSWa/uwkTid5jxYwIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDbRWcv2PAgQx8lvP0IJSemdUAlH7K6\nHTLsSpvHGti2ogIhAJzu//6+TePRjdNL4nhsThttnOk9+lF0Q4UtdXokVZOO\n-----END CERTIFICATE-----\n"
}
```