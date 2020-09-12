Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server and client self-signed SSL certificates with it. Intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based client based SSL certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives.

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
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca domain.com expiryhrs
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server domain.com expiryhrs
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client domain.com expiryhrs
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

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600
2020/09/12 08:26:34 [INFO] generate received request
2020/09/12 08:26:34 [INFO] received CSR
2020/09/12 08:26:34 [INFO] generating key: ecdsa-256
2020/09/12 08:26:34 [INFO] encoded CSR
2020/09/12 08:26:34 [INFO] signed certificate with serial number 533315706181512940721324097802556603906507574964
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5d:6a:b4:0f:8d:8c:10:3c:3a:56:0d:d7:0d:47:8e:d5:bd:e2:8e:b4
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 08:22:00 2020 GMT
            Not After : Sep 10 08:22:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:6a:19:13:4f:de:24:8b:16:32:d9:f0:78:2c:c3:
                    04:09:6f:e7:7a:1f:9b:d0:9e:1d:db:8c:e9:ac:df:
                    d8:4b:4b:f0:43:c6:fd:dd:b1:c2:d7:3a:59:5b:4d:
                    57:c5:c2:2a:83:9a:21:da:e9:d4:18:63:9e:3e:dc:
                    47:b3:a1:d5:e1
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
                63:93:20:78:71:E5:BF:DA:53:EC:BA:2F:33:94:CD:A6:8D:3B:19:A8
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:a7:b4:6f:2b:88:df:67:e8:f0:74:2a:69:df:
         70:0b:58:1c:02:8b:11:f6:ed:e3:82:4b:6b:5c:bd:69:ea:73:
         07:02:21:00:8d:44:4a:30:4d:33:1e:fe:29:ff:82:0f:b2:44:
         da:3c:49:b3:11:43:ec:ee:e6:e6:3c:6b:83:70:b4:ec:e7:77

ca cert: /etc/cfssl/servercerts/centminmod.com.pem
ca key: /etc/cfssl/servercerts/centminmod.com-key.pem
ca csr: /etc/cfssl/servercerts/centminmod.com.csr
ca csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

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
  "serial_number": "533315706181512940721324097802556603906507574964",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T08:22:00Z",
  "not_after": "2030-09-10T08:22:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "63:93:20:78:71:E5:BF:DA:53:EC:BA:2F:33:94:CD:A6:8D:3B:19:A8",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICCDCCAa2gAwIBAgIUXWq0D42MEDw6Vg3XDUeO1b3ijrQwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIwODIyMDBaFw0z\nMDA5MTAwODIyMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARqGRNP3iSLFjLZ8HgswwQJb+d6H5vQnh3bjOms\n39hLS/BDxv3dscLXOllbTVfFwiqDmiHa6dQYY54+3EezodXho28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUY5MgeHHlv9pT7LovM5TNpo07GagwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSQAwRgIhAKe0byuI32fo8HQqad9wC1gcAosR9u3j\ngktrXL1p6nMHAiEAjURKME0zHv4p/4IPskTaPEmzEUPs7ubmPGuDcLTs53c=\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server
2020/09/12 08:27:19 [INFO] generate received request
2020/09/12 08:27:19 [INFO] received CSR
2020/09/12 08:27:19 [INFO] generating key: ecdsa-256
2020/09/12 08:27:19 [INFO] encoded CSR
2020/09/12 08:27:19 [INFO] signed certificate with serial number 403470080592743679586249458456445517242130289143
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            46:ac:39:61:28:0d:a3:e7:3e:e6:a5:bf:3a:17:95:77:1b:dc:d1:f7
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 08:22:00 2020 GMT
            Not After : Sep 10 08:22:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:f1:42:7f:bd:71:a9:0a:1a:78:ac:73:d1:d8:57:
                    9f:24:fe:f7:1b:e6:b8:3f:9c:50:d2:e6:a1:fb:98:
                    a7:bb:bd:2b:fc:d5:77:4f:dc:9e:1b:de:97:8c:5f:
                    0d:81:42:a6:f3:81:44:74:54:44:af:8c:17:0f:32:
                    13:8e:16:2b:47
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
                A1:8C:ED:6F:FA:00:CC:89:1E:C8:44:06:90:6A:4B:0E:FF:8D:13:63
            X509v3 Authority Key Identifier: 
                keyid:22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:93:04:10:4e:7a:8e:d5:78:cd:18:46:bb:cb:
         6d:df:73:bf:02:4e:30:61:42:df:bb:35:e7:19:cb:78:20:3d:
         03:02:20:09:39:c6:b4:3e:95:a7:ca:43:cd:8c:97:db:af:6e:
         16:33:aa:7d:5c:70:97:72:6e:cd:3c:eb:a0:01:2b:8d:36

ca cert: /etc/cfssl/servercerts/server.centminmod.com.pem
ca key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
ca csr: /etc/cfssl/servercerts/server.centminmod.com.csr
ca csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

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
  "serial_number": "403470080592743679586249458456445517242130289143",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T08:22:00Z",
  "not_after": "2030-09-10T08:22:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "22:03:40:71:AC:58:F9:E6:8F:B5:25:9A:FE:EC:24:4E:27:79:8F:16",
  "subject_key_id": "A1:8C:ED:6F:FA:00:CC:89:1E:C8:44:06:90:6A:4B:0E:FF:8D:13:63",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICODCCAd6gAwIBAgIURqw5YSgNo+c+5qW/OheVdxvc0fcwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIwODIyMDBaFw0z\nMDA5MTAwODIyMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8UJ/vXGpChp4rHPR2FefJP73G+a4\nP5xQ0uah+5inu70r/NV3T9yeG96XjF8NgUKm84FEdFREr4wXDzITjhYrR6OBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUoYztb/oAzIkeyEQGkGpLDv+NE2MwHwYDVR0jBBgwFoAU\nIgNAcaxY+eaPtSWa/uwkTid5jxYwIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0gAMEUCIQCTBBBOeo7VeM0YRrvLbd9zvwJOMGFC\n37s15xnLeCA9AwIgCTnGtD6Vp8pDzYyX269uFjOqfVxwl3JuzTzroAErjTY=\n-----END CERTIFICATE-----\n"
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

ca cert: /etc/cfssl/clientcerts/centminmod.com.pem
ca key: /etc/cfssl/clientcerts/centminmod.com-key.pem
ca csr: /etc/cfssl/clientcerts/centminmod.com.csr
ca csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

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

ca cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
ca key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
ca csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
ca csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

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