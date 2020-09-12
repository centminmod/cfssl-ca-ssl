Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server, client and peer self-signed SSL certificates with it. Mainly intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based TLS/SSL client certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives using [gen-client option](#client-ssl-certificate).

Nginx Configuration

```
cp -a /etc/cfssl/centminmod.com-ca-bundle.pem /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem
```

```
ssl_client_certificate /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem;
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

Generate CA & CA Intermediate signed certificates for centminmod.com with 87600 hrs expiry = 10yrs with:

* CA certificate /etc/cfssl/centminmod.com-ca.pem
* CA Intermediate certificate /etc/cfssl/centminmod.com-ca-intermediate.pem
* CA Bundle certificate /etc/cfssl/centminmod.com-ca-bundle.pem

```
./cfssl-ca-ssl.sh gen-ca centminmod.com 87600
--------------------------------------
CA generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca.csr.json | cfssljson -bare centminmod.com-ca

2020/09/12 12:57:16 [INFO] generating a new CA key and certificate from CSR
2020/09/12 12:57:16 [INFO] generate received request
2020/09/12 12:57:16 [INFO] received CSR
2020/09/12 12:57:16 [INFO] generating key: ecdsa-256
2020/09/12 12:57:17 [INFO] encoded CSR
2020/09/12 12:57:17 [INFO] signed certificate with serial number 150057736493308774156569627236546007311200018313

openssl x509 -in centminmod.com-ca.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1a:48:d2:55:dc:d7:44:14:8b:2a:21:c4:9d:54:d9:5d:ff:e7:df:89
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 12:52:00 2020 GMT
            Not After : Sep 10 12:52:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:43:50:1b:80:50:37:c5:1a:5f:db:a1:99:49:f8:
                    d9:d6:7e:0b:62:e5:ca:f0:b3:4a:af:7b:aa:67:24:
                    d9:ed:4e:94:e6:fe:34:7d:bc:2b:b7:59:a9:c5:6a:
                    d7:61:d7:d8:6e:00:08:bf:37:42:c3:87:74:3c:12:
                    ce:26:6c:c9:10
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                D0:8A:95:C6:85:4A:57:7F:5A:3D:0A:9A:6A:5C:90:73:1A:9F:18:04
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:49:3d:81:92:9e:ce:c7:6a:30:09:7e:19:cf:81:
         5f:89:d2:99:0e:ad:de:1a:29:c1:db:4e:f9:f5:0a:44:83:36:
         02:21:00:b3:42:0f:17:64:d9:f4:48:16:b0:4c:8f:54:83:1f:
         e8:ad:66:6f:de:41:41:f1:36:68:1e:ce:79:f7:32:84:fc

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
  "serial_number": "150057736493308774156569627236546007311200018313",
  "not_before": "2020-09-12T12:52:00Z",
  "not_after": "2030-09-10T12:52:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "D0:8A:95:C6:85:4A:57:7F:5A:3D:0A:9A:6A:5C:90:73:1A:9F:18:04",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB2jCCAYCgAwIBAgIUGkjSVdzXRBSLKiHEnVTZXf/n34kwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMjUyMDBaFw0z\nMDA5MTAxMjUyMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARDUBuAUDfFGl/boZlJ+NnWfgti5crws0qve6pn\nJNntTpTm/jR9vCu3WanFatdh19huAAi/N0LDh3Q8Es4mbMkQo0IwQDAOBgNVHQ8B\nAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0IqVxoVKV39aPQqa\nalyQcxqfGAQwCgYIKoZIzj0EAwIDSAAwRQIgST2Bkp7Ox2owCX4Zz4FfidKZDq3e\nGinB20759QpEgzYCIQCzQg8XZNn0SBawTI9Ugx/orWZv3kFB8TZoHs559zKE/A==\n-----END CERTIFICATE-----\n"
}

--------------------------------------
CA Intermediate generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca-intermediate.csr.json | cfssljson -bare centminmod.com-ca-intermediate

2020/09/12 12:57:17 [INFO] generating a new CA key and certificate from CSR
2020/09/12 12:57:17 [INFO] generate received request
2020/09/12 12:57:17 [INFO] received CSR
2020/09/12 12:57:17 [INFO] generating key: ecdsa-256
2020/09/12 12:57:17 [INFO] encoded CSR
2020/09/12 12:57:17 [INFO] signed certificate with serial number 302924499314591647502631354794741669080024009736

cfssl sign -ca /etc/cfssl/centminmod.com-ca.pem -ca-key /etc/cfssl/centminmod.com-ca-key.pem -config /etc/cfssl/profile.json -profile intermediate_ca centminmod.comca-intermediate.csr | cfssljson -bare centminmod.com-ca-intermediate
2020/09/12 12:57:17 [INFO] signed certificate with serial number 475615121865468009329136793859889097323899653701

openssl x509 -in centminmod.com-ca-intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            53:4f:51:d6:4b:d8:eb:ad:a3:fe:8c:47:d2:9b:77:a7:6b:f6:0e:45
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 12:52:00 2020 GMT
            Not After : Sep 10 12:52:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:ce:cd:7a:61:02:c4:8b:13:d3:32:b8:ae:1f:83:
                    12:2a:cd:2f:c1:74:af:f1:13:04:80:f8:4e:8c:3a:
                    0b:59:30:13:53:bf:7b:64:3f:19:33:46:c9:d5:0a:
                    e1:76:4a:e2:53:93:72:86:11:61:a4:f4:94:48:47:
                    f9:15:7c:d8:d5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:11:d0:24:83:b7:ee:d2:1f:9c:93:67:c4:48:9a:
         9b:ef:d7:0b:c4:2a:7f:5d:ad:c1:11:da:b7:da:76:c9:14:33:
         02:21:00:e1:94:dc:55:2b:a4:09:ab:f4:d6:94:86:3c:17:63:
         59:36:c8:aa:2a:b9:50:d8:08:fb:85:ed:8e:27:f2:95:6c

ca intermediate cert: /etc/cfssl/centminmod.com-ca-intermediate.pem
ca intermediate key: /etc/cfssl/centminmod.com-ca-intermediate-key.pem
ca intermediate csr: /etc/cfssl/centminmod.com-ca-intermediate.csr
ca intermediate csr profile: /etc/cfssl/centminmod.com-ca-intermediate.csr.json
ca intermediate profile: /etc/cfssl/profile.json

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
  "serial_number": "475615121865468009329136793859889097323899653701",
  "not_before": "2020-09-12T12:52:00Z",
  "not_after": "2030-09-10T12:52:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB/DCCAaKgAwIBAgIUU09R1kvY662j/oxH0pt3p2v2DkUwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMjUyMDBaFw0z\nMDA5MTAxMjUyMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAATOzXphAsSLE9MyuK4fgxIqzS/BdK/xEwSA+E6M\nOgtZMBNTv3tkPxkzRsnVCuF2SuJTk3KGEWGk9JRIR/kVfNjVo2QwYjAOBgNVHQ8B\nAf8EBAMCAaYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOsmfwBg6i0rRPFG2KO/kTrev7kHMAoGCCqG\nSM49BAMCA0gAMEUCIBHQJIO37tIfnJNnxEiam+/XC8Qqf12twRHat9p2yRQzAiEA\n4ZTcVSukCav01pSGPBdjWTbIqiq5UNgI+4XtjifylWw=\n-----END CERTIFICATE-----\n"
}

CA Bundle generated: /etc/cfssl/centminmod.com-ca-bundle.pem

cat /etc/cfssl/centminmod.com-ca.pem /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-bundle.pem
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:02:38 [INFO] generate received request
2020/09/12 13:02:38 [INFO] received CSR
2020/09/12 13:02:38 [INFO] generating key: ecdsa-256
2020/09/12 13:02:38 [INFO] encoded CSR
2020/09/12 13:02:38 [INFO] signed certificate with serial number 230632741149898333520347063671309303507161469646

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            28:65:ee:06:d7:45:f2:28:c2:58:88:dc:ac:78:2b:e5:eb:a0:52:ce
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 12:58:00 2020 GMT
            Not After : Sep 10 12:58:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:0d:7d:e7:95:31:45:2d:b1:87:11:d5:5b:5c:8c:
                    63:c6:b2:b9:c3:7f:b6:2b:56:b6:f3:fd:fd:0c:ba:
                    c9:f8:ec:73:5a:9a:e4:c9:af:81:4a:1f:19:65:ce:
                    5b:0a:6d:c2:68:e0:0d:9d:76:d4:12:c7:b4:5b:3b:
                    22:78:e4:86:36
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
                26:FB:1C:C2:17:A3:8C:3C:0E:54:7B:8D:DC:BB:97:E0:A7:78:B0:6E
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:7e:ac:fc:ce:64:5f:79:95:d0:48:d9:80:34:78:
         43:ee:c2:88:f3:22:d6:ef:1f:e6:cb:47:d3:00:2d:3b:8d:fe:
         02:20:55:77:11:a4:62:55:6a:c3:11:ad:c8:64:86:7f:db:cb:
         3b:47:cb:21:d0:73:1f:aa:1e:41:58:be:2e:1c:1b:87

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
  "serial_number": "230632741149898333520347063671309303507161469646",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T12:58:00Z",
  "not_after": "2030-09-10T12:58:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "26:FB:1C:C2:17:A3:8C:3C:0E:54:7B:8D:DC:BB:97:E0:A7:78:B0:6E",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICGTCCAcCgAwIBAgIUKGXuBtdF8ijCWIjcrHgr5eugUs4wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMjU4MDBaFw0z\nMDA5MTAxMjU4MDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQNfeeVMUUtsYcR1VtcjGPGsrnDf7YrVrbz/f0M\nusn47HNamuTJr4FKHxllzlsKbcJo4A2ddtQSx7RbOyJ45IY2o4GBMH8wDgYDVR0P\nAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYD\nVR0OBBYEFCb7HMIXo4w8DlR7jdy7l+CneLBuMCsGA1UdEQQkMCKCDmNlbnRtaW5t\nb2QuY29tghAqLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0cAMEQCIH6s/M5k\nX3mV0EjZgDR4Q+7CiPMi1u8f5stH0wAtO43+AiBVdxGkYlVqwxGtyGSGf9vLO0fL\nIdBzH6oeQVi+Lhwbhw==\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:03:34 [INFO] generate received request
2020/09/12 13:03:34 [INFO] received CSR
2020/09/12 13:03:34 [INFO] generating key: ecdsa-256
2020/09/12 13:03:35 [INFO] encoded CSR
2020/09/12 13:03:35 [INFO] signed certificate with serial number 174634815604050242179733004949942022538717814142

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1e:96:e5:5d:ff:a6:5d:f9:88:44:de:21:79:a6:ed:35:bb:e3:dd:7e
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 12:59:00 2020 GMT
            Not After : Sep 10 12:59:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:ea:67:76:3d:05:9e:17:b5:73:0e:56:c9:c1:2e:
                    17:5c:ff:36:d7:82:55:28:4d:23:45:aa:bd:7c:e5:
                    b5:a8:a2:be:92:3b:74:43:9b:9e:32:53:6e:05:e7:
                    6e:4b:8c:8a:e4:83:e6:20:22:08:1d:5c:21:32:b6:
                    67:3e:aa:6b:11
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
                AB:4C:C1:9C:1C:5E:9D:80:0C:D7:FB:34:6A:39:7D:02:CB:83:6D:2C
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:b0:e6:30:53:0f:57:14:f3:37:97:84:5b:2a:
         69:19:13:74:a9:5f:24:23:bf:21:87:27:5e:6a:a1:d3:a5:f9:
         f9:02:20:20:2a:50:6d:a2:65:2f:69:f2:21:b3:d9:99:23:3d:
         49:9d:ea:48:7a:d2:25:f2:01:ef:94:5a:86:9b:86:60:c3

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
  "serial_number": "174634815604050242179733004949942022538717814142",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T12:59:00Z",
  "not_after": "2030-09-10T12:59:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "AB:4C:C1:9C:1C:5E:9D:80:0C:D7:FB:34:6A:39:7D:02:CB:83:6D:2C",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUHpblXf+mXfmIRN4heabtNbvj3X4wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMjU5MDBaFw0z\nMDA5MTAxMjU5MDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAATqZ3Y9BZ4XtXMOVsnBLhdc/zbXglUoTSNFqr18\n5bWoor6SO3RDm54yU24F525LjIrkg+YgIggdXCEytmc+qmsRo28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUq0zBnBxenYAM1/s0ajl9AsuDbSwwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhALDmMFMPVxTzN5eEWyppGRN0qV8kI78h\nhydeaqHTpfn5AiAgKlBtomUvafIhs9mZIz1JnepIetIl8gHvlFqGm4Zgww==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn server.centminmod.com -hostname server.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem server.centminmod.com.csr.json > server.centminmod.com.json
2020/09/12 13:04:09 [INFO] generate received request
2020/09/12 13:04:09 [INFO] received CSR
2020/09/12 13:04:09 [INFO] generating key: ecdsa-256
2020/09/12 13:04:09 [INFO] encoded CSR
2020/09/12 13:04:09 [INFO] signed certificate with serial number 46598388745653789974301431345191330508878561040

cfssljson -f server.centminmod.com.json -bare server.centminmod.com


openssl x509 -in server.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            08:29:8b:44:d1:e1:2e:19:a0:d1:0e:6b:09:eb:34:7e:2a:8a:bf:10
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 12:59:00 2020 GMT
            Not After : Sep 10 12:59:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:c3:ba:66:22:ba:63:a3:a1:04:87:11:d7:0b:95:
                    b8:2d:80:90:e9:95:61:dc:58:ae:32:67:57:28:a1:
                    c5:d1:79:9a:f3:2c:34:16:1e:12:53:08:e9:60:2a:
                    31:7a:c5:48:12:11:02:b9:4e:c1:6c:98:6b:5b:cf:
                    4c:1a:b9:36:02
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
                CA:6D:C6:E6:5B:E5:AC:1B:0E:8F:1C:19:74:53:6E:AE:52:91:8F:70
            X509v3 Authority Key Identifier: 
                keyid:EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:42:13:ba:6e:9c:26:e1:01:99:f6:b4:2f:dc:e0:
         58:48:bf:c7:e7:5a:25:74:09:0e:2c:4f:16:0e:b8:47:7c:7a:
         02:20:2e:8e:8f:ea:07:72:c6:18:73:86:ba:ce:49:ff:1d:7f:
         f6:f1:e1:df:c9:9b:fb:03:5d:f1:aa:a9:19:49:de:e9

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
  "serial_number": "46598388745653789974301431345191330508878561040",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T12:59:00Z",
  "not_after": "2030-09-10T12:59:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07",
  "subject_key_id": "CA:6D:C6:E6:5B:E5:AC:1B:0E:8F:1C:19:74:53:6E:AE:52:91:8F:70",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICNzCCAd6gAwIBAgIUCCmLRNHhLhmg0Q5rCes0fiqKvxAwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMjU5MDBaFw0z\nMDA5MTAxMjU5MDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw7pmIrpjo6EEhxHXC5W4LYCQ6ZVh\n3FiuMmdXKKHF0Xma8yw0Fh4SUwjpYCoxesVIEhECuU7BbJhrW89MGrk2AqOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUym3G5lvlrBsOjxwZdFNurlKRj3AwHwYDVR0jBBgwFoAU\n6yZ/AGDqLStE8UbYo7+ROt6/uQcwIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0cAMEQCIEITum6cJuEBmfa0L9zgWEi/x+daJXQJ\nDixPFg64R3x6AiAujo/qB3LGGHOGus5J/x1/9vHh38mb+wNd8aqpGUne6Q==\n-----END CERTIFICATE-----\n"
}
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:04:42 [INFO] generate received request
2020/09/12 13:04:42 [INFO] received CSR
2020/09/12 13:04:42 [INFO] generating key: ecdsa-256
2020/09/12 13:04:42 [INFO] encoded CSR
2020/09/12 13:04:42 [INFO] signed certificate with serial number 583605021620236404490827357599685976341855883610

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            66:39:c1:17:10:b5:58:fd:61:27:a9:25:65:bc:49:85:7f:c0:51:5a
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:00:00 2020 GMT
            Not After : Sep 10 13:00:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:10:ed:0d:e3:8f:a0:61:cf:fc:5d:50:7c:ef:04:
                    82:e2:8a:2a:04:3f:41:83:b0:46:73:39:c3:48:6f:
                    02:b2:f0:ef:0d:60:6b:9c:de:5d:a9:2e:db:4f:a5:
                    98:c3:ba:da:f1:e1:f2:0d:16:17:30:b3:14:a6:89:
                    d5:86:b8:aa:8c
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
                4F:9F:53:3C:17:4A:E9:C0:6A:23:F2:E7:E3:5B:F6:B8:D4:F7:85:D9
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:86:79:b0:d0:cf:17:47:d8:b2:b3:1b:49:48:
         89:25:d8:d5:dd:c9:3f:87:f8:5f:ec:10:cb:a2:9f:58:89:ad:
         27:02:20:1c:1a:18:e3:7e:0e:2c:c0:20:3c:1f:c6:e7:45:f2:
         29:27:31:72:ba:a6:02:82:32:16:b4:71:a4:7e:bb:ed:f5

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
  "serial_number": "583605021620236404490827357599685976341855883610",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T13:00:00Z",
  "not_after": "2030-09-10T13:00:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "4F:9F:53:3C:17:4A:E9:C0:6A:23:F2:E7:E3:5B:F6:B8:D4:F7:85:D9",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICBzCCAa2gAwIBAgIUZjnBFxC1WP1hJ6klZbxJhX/AUVowCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMzAwMDBaFw0z\nMDA5MTAxMzAwMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQQ7Q3jj6Bhz/xdUHzvBILiiioEP0GDsEZzOcNI\nbwKy8O8NYGuc3l2pLttPpZjDutrx4fINFhcwsxSmidWGuKqMo28wbTAOBgNVHQ8B\nAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV\nHQ4EFgQUT59TPBdK6cBqI/Ln41v2uNT3hdkwGQYDVR0RBBIwEIIOY2VudG1pbm1v\nZC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAIZ5sNDPF0fYsrMbSUiJJdjV3ck/h/hf\n7BDLop9Yia0nAiAcGhjjfg4swCA8H8bnRfIpJzFyuqYCgjIWtHGkfrvt9Q==\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn client.centminmod.com -hostname client.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem client.centminmod.com.csr.json > client.centminmod.com.json
2020/09/12 13:05:09 [INFO] generate received request
2020/09/12 13:05:09 [INFO] received CSR
2020/09/12 13:05:09 [INFO] generating key: ecdsa-256
2020/09/12 13:05:09 [INFO] encoded CSR
2020/09/12 13:05:09 [INFO] signed certificate with serial number 195215568395031250743425933051693886324494469655

cfssljson -f client.centminmod.com.json -bare client.centminmod.com


openssl x509 -in client.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:31:c4:d2:9a:30:84:72:e2:1d:1b:6e:e9:61:5f:cc:65:0a:8a:17
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:00:00 2020 GMT
            Not After : Sep 10 13:00:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e7:54:57:fb:e7:84:af:1a:13:8e:21:d6:3c:53:
                    0c:d1:2c:c0:ce:ed:9a:b2:79:96:c4:bc:2a:96:49:
                    ee:78:64:ff:66:d0:97:05:77:86:38:96:37:c9:f8:
                    d1:64:03:de:8f:57:38:95:38:fb:0e:8c:2c:42:a3:
                    a4:8c:07:30:8d
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
                AD:B7:CB:B5:9E:56:AC:DB:76:4A:AB:D0:A4:8E:CF:FC:32:82:45:8F
            X509v3 Authority Key Identifier: 
                keyid:EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:f6:aa:30:69:65:98:21:3f:b7:a8:a2:54:a3:
         cd:f6:1f:1d:78:f3:91:42:0b:ef:5a:07:e4:3f:4d:02:96:13:
         8d:02:21:00:e7:25:75:86:1f:f1:f2:73:24:ef:61:47:df:3e:
         7c:a6:f1:5d:8d:b0:05:33:ec:9a:22:aa:56:2e:23:13:8f:1e

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
  "serial_number": "195215568395031250743425933051693886324494469655",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-12T13:00:00Z",
  "not_after": "2030-09-10T13:00:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07",
  "subject_key_id": "AD:B7:CB:B5:9E:56:AC:DB:76:4A:AB:D0:A4:8E:CF:FC:32:82:45:8F",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICOTCCAd6gAwIBAgIUIjHE0powhHLiHRtu6WFfzGUKihcwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMzAwMDBaFw0z\nMDA5MTAxMzAwMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE51RX++eErxoTjiHWPFMM0SzAzu2a\nsnmWxLwqlknueGT/ZtCXBXeGOJY3yfjRZAPej1c4lTj7DowsQqOkjAcwjaOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUrbfLtZ5WrNt2SqvQpI7P/DKCRY8wHwYDVR0jBBgwFoAU\n6yZ/AGDqLStE8UbYo7+ROt6/uQcwIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQD2qjBpZZghP7eoolSjzfYfHXjzkUIL\n71oH5D9NApYTjQIhAOcldYYf8fJzJO9hR98+fKbxXY2wBTPsmiKqVi4jE48e\n-----END CERTIFICATE-----\n"
}
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard

cfssl gencert -config /etc/cfssl/profile.json -profile peer -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:05:48 [INFO] generate received request
2020/09/12 13:05:48 [INFO] received CSR
2020/09/12 13:05:48 [INFO] generating key: ecdsa-256
2020/09/12 13:05:48 [INFO] encoded CSR
2020/09/12 13:05:48 [INFO] signed certificate with serial number 53335912518482692307540007920694465212839499471

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            09:57:aa:3f:a7:50:62:83:31:5f:fa:a4:5d:6e:a5:2b:f9:ea:16:cf
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:01:00 2020 GMT
            Not After : Sep 10 13:01:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:8a:ae:87:8b:89:51:ed:1a:5b:30:31:99:2b:aa:
                    be:f3:82:ca:29:a9:32:61:f8:e7:da:7b:1e:84:9f:
                    ea:a0:9f:ec:b1:ec:57:42:17:88:3c:37:a8:87:d7:
                    a4:b9:66:ec:13:3c:e2:04:76:48:8e:4e:d1:d1:ed:
                    31:ad:65:7e:1f
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
                23:24:C4:3D:87:9E:F5:84:D3:63:57:D3:35:AC:40:48:DE:0C:89:0B
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:f4:93:30:8a:42:b0:1c:96:1e:7a:b5:ec:31:
         97:f0:ce:1a:8a:e1:ba:fb:da:1c:85:22:80:bf:9c:c0:47:60:
         22:02:21:00:b2:51:f9:d5:0a:ef:84:5b:b9:ab:7d:03:9f:fe:
         94:19:3a:16:cc:d8:e8:a2:f2:82:f9:30:8a:21:05:43:3c:40

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
  "serial_number": "53335912518482692307540007920694465212839499471",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T13:01:00Z",
  "not_after": "2030-09-10T13:01:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "23:24:C4:3D:87:9E:F5:84:D3:63:57:D3:35:AC:40:48:DE:0C:89:0B",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICJjCCAcugAwIBAgIUCVeqP6dQYoMxX/qkXW6lK/nqFs8wCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMzAxMDBaFw0z\nMDA5MTAxMzAxMDBaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASKroeLiVHtGlswMZkrqr7zgsopqTJh+Ofaex6E\nn+qgn+yx7FdCF4g8N6iH16S5ZuwTPOIEdkiOTtHR7TGtZX4fo4GMMIGJMA4GA1Ud\nDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDAYDVR0T\nAQH/BAIwADAdBgNVHQ4EFgQUIyTEPYee9YTTY1fTNaxASN4MiQswKwYDVR0RBCQw\nIoIOY2VudG1pbm1vZC5jb22CECouY2VudG1pbm1vZC5jb20wCgYIKoZIzj0EAwID\nSQAwRgIhAPSTMIpCsByWHnq17DGX8M4aiuG6+9ochSKAv5zAR2AiAiEAslH51Qrv\nhFu5q30Dn/6UGToWzNjoovKC+TCKIQVDPEA=\n-----END CERTIFICATE-----\n"
}
```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer

cfssl gencert -config /etc/cfssl/profile.json -profile peer -cn peer.centminmod.com -hostname peer.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem peer.centminmod.com.csr.json > peer.centminmod.com.json
2020/09/12 13:06:24 [INFO] generate received request
2020/09/12 13:06:24 [INFO] received CSR
2020/09/12 13:06:24 [INFO] generating key: ecdsa-256
2020/09/12 13:06:24 [INFO] encoded CSR
2020/09/12 13:06:24 [INFO] signed certificate with serial number 259982623557110093038084835114256286224157936901

cfssljson -f peer.centminmod.com.json -bare peer.centminmod.com


openssl x509 -in peer.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2d:8a:06:27:42:23:45:82:fc:b1:45:a7:83:ce:8e:14:ba:2a:8d:05
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:01:00 2020 GMT
            Not After : Sep 10 13:01:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:b6:c2:4e:6f:f5:36:34:5b:6f:90:89:90:43:3e:
                    c3:8f:f5:fc:a7:f3:c9:df:9c:a3:91:8d:ce:b1:97:
                    1f:67:29:de:f0:41:b9:f5:26:7d:0e:26:9a:01:55:
                    f5:66:85:97:58:5b:2b:8b:b7:7f:b8:cf:2a:de:89:
                    0a:70:3f:9a:3e
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
                8C:84:64:0F:5D:79:7F:22:59:C7:72:60:49:40:E0:D8:24:BF:4E:B3
            X509v3 Authority Key Identifier: 
                keyid:EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:86:ca:cc:e4:8e:50:6c:0c:f3:a8:0a:ec:2c:
         bc:be:57:c5:0c:ca:e1:c8:b3:25:27:0d:a2:8e:c9:ca:09:bb:
         72:02:21:00:f6:4f:5b:9f:f3:8e:c9:f4:f0:33:5b:d0:ba:e5:
         a6:31:8a:dc:23:9f:a8:fb:c0:cf:3c:0c:4b:2d:75:1c:18:ff

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
  "serial_number": "259982623557110093038084835114256286224157936901",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-12T13:01:00Z",
  "not_after": "2030-09-10T13:01:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07",
  "subject_key_id": "8C:84:64:0F:5D:79:7F:22:59:C7:72:60:49:40:E0:D8:24:BF:4E:B3",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICPzCCAeSgAwIBAgIULYoGJ0IjRYL8sUWng86OFLoqjQUwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMzAxMDBaFw0z\nMDA5MTAxMzAxMDBaMFAxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEcMBoGA1UEAxMTcGVlci5jZW50bWlubW9kLmNvbTBZ\nMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLbCTm/1NjRbb5CJkEM+w4/1/Kfzyd+c\no5GNzrGXH2cp3vBBufUmfQ4mmgFV9WaFl1hbK4u3f7jPKt6JCnA/mj6jgaAwgZ0w\nDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAM\nBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSMhGQPXXl/IlnHcmBJQODYJL9OszAfBgNV\nHSMEGDAWgBTrJn8AYOotK0TxRtijv5E63r+5BzAeBgNVHREEFzAVghNwZWVyLmNl\nbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQCGyszkjlBsDPOoCuwsvL5X\nxQzK4cizJScNoo7Jygm7cgIhAPZPW5/zjsn08DNb0LrlpjGK3COfqPvAzzwMSy11\nHBj/\n-----END CERTIFICATE-----\n"
}
```