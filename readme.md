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
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server ca-domain.com expiryhrs server sitedomain.com

Generate TLS server wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server ca-domain.com expiryhrs wildcard sitedomain.com

Generate TLS Client certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client ca-domain.com expiryhrs client sitedomain.com

Generate TLS Peer certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer ca-domain.com expiryhrs peer sitedomain.com

Generate TLS Peer wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer ca-domain.com expiryhrs wildcard sitedomain.com
```

# CA Certificate

Generate CA & CA Intermediate signed certificates for centminmod.com with 87600 hrs expiry = 10yrs with:

* CA certificate /etc/cfssl/centminmod.com-ca.pem
* CA Intermediate certificate /etc/cfssl/centminmod.com-ca-intermediate.pem
* CA Bundle certificate /etc/cfssl/centminmod.com-ca-bundle.pem

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600
--------------------------------------
CA generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca.csr.json | cfssljson -bare centminmod.com-ca

2020/09/12 22:04:50 [INFO] generating a new CA key and certificate from CSR
2020/09/12 22:04:50 [INFO] generate received request
2020/09/12 22:04:50 [INFO] received CSR
2020/09/12 22:04:50 [INFO] generating key: ecdsa-256
2020/09/12 22:04:50 [INFO] encoded CSR
2020/09/12 22:04:50 [INFO] signed certificate with serial number 324942453558285070022802152586461918656054052293

openssl x509 -in centminmod.com-ca.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            38:ea:ec:6e:40:0f:fe:4e:6e:a1:6e:c4:a8:4d:20:89:2d:22:45:c5
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 22:00:00 2020 GMT
            Not After : Sep 10 22:00:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:a5:15:d5:8b:5b:cb:3f:42:92:12:dd:25:ea:80:
                    1b:e6:c7:72:1e:89:ae:5a:24:19:f8:38:dc:eb:47:
                    2c:87:5f:9d:02:13:00:af:54:ad:18:90:30:1d:a5:
                    4c:29:5c:7d:6c:c2:0d:68:3c:ad:9c:6d:e1:7d:17:
                    62:1f:1f:f8:5f
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                4D:19:C6:A2:EA:60:D6:D6:85:E8:F6:DE:C2:D4:6D:F7:58:F1:E8:F9
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:cb:60:21:35:2e:cc:2b:a0:a8:7b:3a:b2:b2:
         a4:72:a0:f0:a1:9e:4a:6b:03:16:88:63:ed:62:d0:68:23:86:
         3b:02:20:17:b0:c0:ce:58:9c:60:21:2e:7c:50:1e:bb:59:a2:
         0d:58:30:28:50:3d:fc:02:5b:b8:0b:8a:67:11:b1:87:67

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca key: /etc/cfssl/centminmod.com-ca-key.pem
ca csr: /etc/cfssl/centminmod.com-ca.csr
ca csr profile: /etc/cfssl/centminmod.com-ca.csr.json
ca profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "centminmod.com"
    ]
  },
  "serial_number": "324942453558285070022802152586461918656054052293",
  "not_before": "2020-09-12T22:00:00Z",
  "not_after": "2030-09-10T22:00:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "4D:19:C6:A2:EA:60:D6:D6:85:E8:F6:DE:C2:D4:6D:F7:58:F1:E8:F9",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB/jCCAaSgAwIBAgIUOOrsbkAP/k5uoW7EqE0giS0iRcUwCgYIKoZIzj0EAwIw\nXTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAe\nFw0yMDA5MTIyMjAwMDBaFw0zMDA5MTAyMjAwMDBaMF0xCzAJBgNVBAYTAlVTMQsw\nCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UECxMHUm9v\ndCBDQTEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAASlFdWLW8s/QpIS3SXqgBvmx3Ieia5aJBn4ONzrRyyHX50CEwCvVK0Y\nkDAdpUwpXH1swg1oPK2cbeF9F2IfH/hfo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUTRnGoupg1taF6PbewtRt91jx6PkwCgYI\nKoZIzj0EAwIDSAAwRQIhAMtgITUuzCugqHs6srKkcqDwoZ5KawMWiGPtYtBoI4Y7\nAiAXsMDOWJxgIS58UB67WaINWDAoUD38Alu4C4pnEbGHZw==\n-----END CERTIFICATE-----\n"
}

--------------------------------------
CA Intermediate generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca-intermediate.csr.json | cfssljson -bare centminmod.com-ca-intermediate

2020/09/12 22:04:50 [INFO] generating a new CA key and certificate from CSR
2020/09/12 22:04:50 [INFO] generate received request
2020/09/12 22:04:50 [INFO] received CSR
2020/09/12 22:04:50 [INFO] generating key: ecdsa-256
2020/09/12 22:04:50 [INFO] encoded CSR
2020/09/12 22:04:50 [INFO] signed certificate with serial number 386334214604305976372879152253444336536490589410

cfssl sign -ca /etc/cfssl/centminmod.com-ca.pem -ca-key /etc/cfssl/centminmod.com-ca-key.pem -config /etc/cfssl/profile.json -profile intermediate_ca centminmod.comca-intermediate.csr | cfssljson -bare centminmod.com-ca-intermediate
2020/09/12 22:04:50 [INFO] signed certificate with serial number 446690807988893825891068299615638059845636989711

openssl x509 -in centminmod.com-ca-intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4e:3e:4e:ff:63:51:f9:36:03:3c:24:ff:91:12:9b:e3:2e:be:23:0f
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 22:00:00 2020 GMT
            Not After : Sep 10 22:00:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:2c:37:b6:1f:08:5f:27:c7:6c:db:c0:e6:4b:96:
                    7d:03:05:1d:75:2f:9e:86:ec:44:3e:cf:57:36:97:
                    1d:41:5e:e6:cc:95:a8:50:30:49:89:f3:1b:cc:7e:
                    da:aa:ef:b8:ce:8d:df:bb:fe:a2:11:32:41:26:29:
                    69:5b:b1:a1:63
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
                82:28:38:0A:B8:11:26:D0:79:9C:8C:C6:5C:78:81:1C:D9:38:17:2F
            X509v3 Authority Key Identifier: 
                keyid:4D:19:C6:A2:EA:60:D6:D6:85:E8:F6:DE:C2:D4:6D:F7:58:F1:E8:F9

    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:33:19:cb:95:d4:2d:d0:1a:2a:dd:75:50:b9:7a:
         4e:da:b7:5c:bb:13:67:a0:2d:d1:52:c0:ef:2c:ef:c3:da:a9:
         02:20:62:45:38:15:45:75:61:f3:d8:08:46:be:ae:12:ad:e0:
         bf:e5:32:89:05:8b:9a:b0:23:b9:46:51:8f:62:45:6b

ca intermediate cert: /etc/cfssl/centminmod.com-ca-intermediate.pem
ca intermediate key: /etc/cfssl/centminmod.com-ca-intermediate-key.pem
ca intermediate csr: /etc/cfssl/centminmod.com-ca-intermediate.csr
ca intermediate csr profile: /etc/cfssl/centminmod.com-ca-intermediate.csr.json
ca intermediate profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "centminmod.com"
    ]
  },
  "serial_number": "446690807988893825891068299615638059845636989711",
  "not_before": "2020-09-12T22:00:00Z",
  "not_after": "2030-09-10T22:00:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "4D:19:C6:A2:EA:60:D6:D6:85:E8:F6:DE:C2:D4:6D:F7:58:F1:E8:F9",
  "subject_key_id": "82:28:38:0A:B8:11:26:D0:79:9C:8C:C6:5C:78:81:1C:D9:38:17:2F",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICSjCCAfGgAwIBAgIUTj5O/2NR+TYDPCT/kRKb4y6+Iw8wCgYIKoZIzj0EAwIw\nXTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAe\nFw0yMDA5MTIyMjAwMDBaFw0zMDA5MTAyMjAwMDBaMGUxCzAJBgNVBAYTAlVTMQsw\nCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEYMBYGA1UECxMPSW50\nZXJtZWRpYXRlIENBMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABCw3th8IXyfHbNvA5kuWfQMFHXUvnobsRD7PVzaXHUFe\n5syVqFAwSYnzG8x+2qrvuM6N37v+ohEyQSYpaVuxoWOjgYYwgYMwDgYDVR0PAQH/\nBAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8E\nCDAGAQH/AgEAMB0GA1UdDgQWBBSCKDgKuBEm0HmcjMZceIEc2TgXLzAfBgNVHSME\nGDAWgBRNGcai6mDW1oXo9t7C1G33WPHo+TAKBggqhkjOPQQDAgNHADBEAiAzGcuV\n1C3QGirddVC5ek7at1y7E2egLdFSwO8s78PaqQIgYkU4FUV1YfPYCEa+rhKt4L/l\nMokFi5qwI7lGUY9iRWs=\n-----END CERTIFICATE-----\n"
}

CA Bundle generated: /etc/cfssl/centminmod.com-ca-bundle.pem

cat /etc/cfssl/centminmod.com-ca.pem /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-bundle.pem
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:22:33 [INFO] generate received request
2020/09/12 13:22:33 [INFO] received CSR
2020/09/12 13:22:33 [INFO] generating key: ecdsa-256
2020/09/12 13:22:33 [INFO] encoded CSR
2020/09/12 13:22:33 [INFO] signed certificate with serial number 179782923004220395668081928492668890196493523529

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1f:7d:be:bd:ea:19:4a:08:aa:27:a8:6a:09:a9:ed:89:c4:ec:da:49
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:18:00 2020 GMT
            Not After : Sep 10 13:18:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:d0:d2:b7:1b:49:d5:23:48:55:c7:14:32:e2:e0:
                    92:d3:bf:dc:be:0e:f7:e8:67:1b:10:4e:8d:30:b8:
                    e5:81:31:38:87:b7:f0:23:bf:93:4c:b2:94:56:a7:
                    f5:c8:fd:9b:a1:f0:92:0a:27:78:39:22:3c:eb:c4:
                    8d:67:c0:ac:cb
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
                15:23:46:8D:98:0E:79:7E:05:36:40:17:7F:FE:F7:2A:7C:06:33:3A
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:a4:07:f6:c6:0f:e3:19:4e:9b:6e:31:0c:c3:
         12:fd:be:61:f1:4b:30:9c:af:84:45:16:24:3d:85:b7:84:07:
         93:02:21:00:f5:0c:d8:74:cc:76:7d:d4:36:2b:dc:d6:31:3d:
         00:a7:c7:2d:05:92:92:82:82:6c:f6:10:53:8d:c2:91:ef:fe

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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "179782923004220395668081928492668890196493523529",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T13:18:00Z",
  "not_after": "2030-09-10T13:18:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "15:23:46:8D:98:0E:79:7E:05:36:40:17:7F:FE:F7:2A:7C:06:33:3A",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICVzCCAfygAwIBAgIUH32+veoZSgiqJ6hqCanticTs2kkwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTgwMFoXDTMwMDkxMDEzMTgwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNDS\ntxtJ1SNIVccUMuLgktO/3L4O9+hnGxBOjTC45YExOIe38CO/k0yylFan9cj9m6Hw\nkgoneDkiPOvEjWfArMujgaMwgaAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBUjRo2YDnl+BTZAF3/+\n9yp8BjM6MB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMCsGA1UdEQQk\nMCKCDmNlbnRtaW5tb2QuY29tghAqLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMC\nA0kAMEYCIQCkB/bGD+MZTptuMQzDEv2+YfFLMJyvhEUWJD2Ft4QHkwIhAPUM2HTM\ndn3UNivc1jE9AKfHLQWSkoKCbPYQU43Cke/+\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:23:14 [INFO] generate received request
2020/09/12 13:23:14 [INFO] received CSR
2020/09/12 13:23:14 [INFO] generating key: ecdsa-256
2020/09/12 13:23:14 [INFO] encoded CSR
2020/09/12 13:23:14 [INFO] signed certificate with serial number 603573150065020846116360668497768876574050440426

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:b9:27:f6:86:0b:6f:91:ae:9f:5b:87:85:d5:a4:ff:8b:09:54:ea
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:18:00 2020 GMT
            Not After : Sep 10 13:18:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:56:b3:c3:da:35:e4:34:6e:69:c5:9a:f3:70:f6:
                    44:ff:1d:69:2c:33:c8:6d:7e:62:8f:4e:27:c5:a5:
                    3f:53:76:b2:19:a6:30:4e:7f:fa:a2:dc:75:9c:4f:
                    c1:c2:66:64:79:f4:47:8c:3c:1a:b6:a4:01:9f:8f:
                    b7:06:40:46:54
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
                8D:E5:65:B1:09:EF:9B:7D:DD:F6:6A:54:4A:F4:82:A7:3C:79:6E:52
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:e1:10:4d:40:83:b6:4d:4d:81:71:7c:18:a9:
         f2:46:bd:88:84:2d:3e:47:09:90:13:13:6a:a7:8e:00:dc:70:
         f8:02:21:00:9f:7f:52:96:3e:ce:cb:2e:78:3e:99:6e:34:d8:
         86:0f:2c:54:1e:2c:9a:ed:42:ca:de:b4:83:1f:d5:b0:7c:56

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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "603573150065020846116360668497768876574050440426",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T13:18:00Z",
  "not_after": "2030-09-10T13:18:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "8D:E5:65:B1:09:EF:9B:7D:DD:F6:6A:54:4A:F4:82:A7:3C:79:6E:52",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeqgAwIBAgIUabkn9oYLb5Gun1uHhdWk/4sJVOowCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTgwMFoXDTMwMDkxMDEzMTgwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFaz\nw9o15DRuacWa83D2RP8daSwzyG1+Yo9OJ8WlP1N2shmmME5/+qLcdZxPwcJmZHn0\nR4w8GrakAZ+PtwZARlSjgZEwgY4wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFI3lZbEJ75t93fZqVEr0\ngqc8eW5SMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMBkGA1UdEQQS\nMBCCDmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDhEE1Ag7ZNTYFx\nfBip8ka9iIQtPkcJkBMTaqeOANxw+AIhAJ9/UpY+zssueD6ZbjTYhg8sVB4smu1C\nyt60gx/VsHxW\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
* server key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/server.centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn server.centminmod.com -hostname server.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem server.centminmod.com.csr.json > server.centminmod.com.json
2020/09/12 13:23:57 [INFO] generate received request
2020/09/12 13:23:57 [INFO] received CSR
2020/09/12 13:23:57 [INFO] generating key: ecdsa-256
2020/09/12 13:23:57 [INFO] encoded CSR
2020/09/12 13:23:57 [INFO] signed certificate with serial number 130338219757322254164091633097459462239291093100

cfssljson -f server.centminmod.com.json -bare server.centminmod.com


openssl x509 -in server.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            16:d4:91:62:8d:6b:18:f0:f2:a7:7e:68:9f:14:71:1b:2a:2a:b0:6c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:19:00 2020 GMT
            Not After : Sep 10 13:19:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e9:11:94:43:93:2c:39:75:22:3a:2b:c0:5f:c4:
                    36:86:f5:05:2c:95:73:db:1d:7e:e3:7b:e6:3d:8b:
                    03:c7:e7:31:31:b3:ae:04:45:15:18:50:64:3e:f9:
                    90:99:b9:aa:25:44:c9:45:69:ae:73:93:ef:3f:3e:
                    a0:93:5b:8a:3d
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
                8D:51:02:DA:58:1A:15:C8:03:30:FB:41:F2:38:70:AA:76:2D:1C:9B
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:0b:48:09:00:7e:29:cd:ce:8c:fa:a5:06:6b:35:
         5c:be:7d:bc:1b:06:a7:e8:5b:f0:65:5e:cc:a9:9b:f9:15:d4:
         02:20:2a:23:26:0c:e7:da:ae:03:13:af:d7:db:40:9b:35:1b:
         5e:41:69:6d:47:f5:5a:9e:15:0f:47:37:79:ab:e4:24

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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "130338219757322254164091633097459462239291093100",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T13:19:00Z",
  "not_after": "2030-09-10T13:19:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "8D:51:02:DA:58:1A:15:C8:03:30:FB:41:F2:38:70:AA:76:2D:1C:9B",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICUTCCAfigAwIBAgIUFtSRYo1rGPDyp35onxRxGyoqsGwwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTkwMFoXDTMwMDkxMDEzMTkwMFowUjELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR4wHAYD\nVQQDExVzZXJ2ZXIuY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAATpEZRDkyw5dSI6K8BfxDaG9QUslXPbHX7je+Y9iwPH5zExs64ERRUYUGQ+\n+ZCZuaolRMlFaa5zk+8/PqCTW4o9o4GYMIGVMA4GA1UdDwEB/wQEAwIFoDATBgNV\nHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSNUQLaWBoV\nyAMw+0HyOHCqdi0cmzAfBgNVHSMEGDAWgBQgKcMr7F1AjG8wregAhVwvoR636zAg\nBgNVHREEGTAXghVzZXJ2ZXIuY2VudG1pbm1vZC5jb20wCgYIKoZIzj0EAwIDRwAw\nRAIgC0gJAH4pzc6M+qUGazVcvn28Gwan6FvwZV7MqZv5FdQCICojJgzn2q4DE6/X\n20CbNRteQWltR/VanhUPRzd5q+Qk\n-----END CERTIFICATE-----\n"
}
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/centminmod.com.pem
* client key: /etc/cfssl/clientcerts/centminmod.com-key.pem
* client csr: /etc/cfssl/clientcerts/centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:42:34 [INFO] generate received request
2020/09/12 13:42:34 [INFO] received CSR
2020/09/12 13:42:34 [INFO] generating key: ecdsa-256
2020/09/12 13:42:35 [INFO] encoded CSR
2020/09/12 13:42:35 [INFO] signed certificate with serial number 116593214473436573018806009057935572153607367296

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            14:6c:38:76:64:f3:79:e4:7f:fa:be:d0:cb:be:3e:3a:44:67:aa:80
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:38:00 2020 GMT
            Not After : Sep 10 13:38:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:8e:7f:64:da:1a:c9:bd:57:b6:e1:1f:09:56:19:
                    fe:8a:a4:4f:df:03:1a:29:ab:20:6a:46:fe:81:3d:
                    c6:57:94:55:c0:ab:ad:47:2f:1f:79:5f:d7:52:23:
                    f4:b3:fd:99:a8:a3:59:82:b5:86:e8:fd:92:ed:0f:
                    83:69:9a:2c:da
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
                CE:B5:46:2E:E4:F3:9F:34:B2:2C:F0:E8:9C:FB:3F:CB:D1:F3:29:82
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:87:b7:5f:1c:a3:47:cd:42:a8:76:25:ef:0d:
         40:81:be:77:66:99:38:27:84:3a:c4:a0:e5:fc:15:55:4b:14:
         b9:02:20:53:47:55:b4:d0:59:82:b2:27:5f:86:d7:b3:a0:ff:
         2f:01:e2:6f:d9:7b:94:c9:17:fe:73:e6:25:0b:d3:f1:4e

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/centminmod.com.p12 -inkey /etc/cfssl/clientcerts/centminmod.com-key.pem -in /etc/cfssl/clientcerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "116593214473436573018806009057935572153607367296",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T13:38:00Z",
  "not_after": "2030-09-10T13:38:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "CE:B5:46:2E:E4:F3:9F:34:B2:2C:F0:E8:9C:FB:3F:CB:D1:F3:29:82",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRDCCAeqgAwIBAgIUFGw4dmTzeeR/+r7Qy74+OkRnqoAwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMzgwMFoXDTMwMDkxMDEzMzgwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5/\nZNoayb1XtuEfCVYZ/oqkT98DGimrIGpG/oE9xleUVcCrrUcvH3lf11Ij9LP9maij\nWYK1huj9ku0Pg2maLNqjgZEwgY4wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFM61Ri7k8580sizw6Jz7\nP8vR8ymCMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMBkGA1UdEQQS\nMBCCDmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0gAMEUCIQCHt18co0fNQqh2\nJe8NQIG+d2aZOCeEOsSg5fwVVUsUuQIgU0dVtNBZgrInX4bXs6D/LwHib9l7lMkX\n/nPmJQvT8U4=\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
* client key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
* client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn client.centminmod.com -hostname client.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem client.centminmod.com.csr.json > client.centminmod.com.json
2020/09/12 13:43:10 [INFO] generate received request
2020/09/12 13:43:10 [INFO] received CSR
2020/09/12 13:43:10 [INFO] generating key: ecdsa-256
2020/09/12 13:43:10 [INFO] encoded CSR
2020/09/12 13:43:10 [INFO] signed certificate with serial number 353947124458801266164450314032948551038862726321

cfssljson -f client.centminmod.com.json -bare client.centminmod.com


openssl x509 -in client.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3d:ff:89:b9:3a:50:1d:f0:9d:f4:e0:93:44:58:de:57:09:7d:94:b1
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:38:00 2020 GMT
            Not After : Sep 10 13:38:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e9:5e:72:74:74:2c:ce:9d:da:4c:6a:5e:57:eb:
                    29:8b:57:43:f2:b3:08:5c:dd:7f:bf:77:9f:1d:80:
                    b3:68:04:8b:e2:aa:3f:40:a9:43:00:11:1e:f7:0c:
                    aa:05:10:1a:dd:37:47:8d:5e:77:67:2b:d7:0d:60:
                    e1:02:30:23:db
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
                0F:AB:81:F5:7B:D5:4D:F3:0C:79:2E:F3:66:AA:A1:8C:46:F3:FA:ED
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:22:e4:99:24:5f:06:76:2f:d0:a2:f4:ae:ed:6f:
         67:ef:41:70:1e:d8:97:5d:2f:85:18:17:93:6c:46:8d:36:f2:
         02:20:07:c0:1f:06:83:64:c7:56:42:bc:39:67:4e:66:b6:91:
         83:a7:ef:dd:20:20:c4:e8:81:b3:cd:94:8d:ee:c7:ae

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/client.centminmod.com.p12 -inkey /etc/cfssl/clientcerts/client.centminmod.com-key.pem -in /etc/cfssl/clientcerts/client.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "353947124458801266164450314032948551038862726321",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-12T13:38:00Z",
  "not_after": "2030-09-10T13:38:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "0F:AB:81:F5:7B:D5:4D:F3:0C:79:2E:F3:66:AA:A1:8C:46:F3:FA:ED",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICUTCCAfigAwIBAgIUPf+JuTpQHfCd9OCTRFjeVwl9lLEwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMzgwMFoXDTMwMDkxMDEzMzgwMFowUjELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR4wHAYD\nVQQDExVjbGllbnQuY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAATpXnJ0dCzOndpMal5X6ymLV0Pyswhc3X+/d58dgLNoBIviqj9AqUMAER73\nDKoFEBrdN0eNXndnK9cNYOECMCPbo4GYMIGVMA4GA1UdDwEB/wQEAwIFoDATBgNV\nHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQPq4H1e9VN\n8wx5LvNmqqGMRvP67TAfBgNVHSMEGDAWgBQgKcMr7F1AjG8wregAhVwvoR636zAg\nBgNVHREEGTAXghVjbGllbnQuY2VudG1pbm1vZC5jb20wCgYIKoZIzj0EAwIDRwAw\nRAIgIuSZJF8Gdi/QovSu7W9n70FwHtiXXS+FGBeTbEaNNvICIAfAHwaDZMdWQrw5\nZ05mtpGDp+/dICDE6IGzzZSN7seu\n-----END CERTIFICATE-----\n"
}
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/centminmod.com.pem
* peer key: /etc/cfssl/peercerts/centminmod.com-key.pem
* peer csr: /etc/cfssl/peercerts/centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:48:15 [INFO] generate received request
2020/09/12 13:48:15 [INFO] received CSR
2020/09/12 13:48:15 [INFO] generating key: ecdsa-256
2020/09/12 13:48:16 [INFO] encoded CSR
2020/09/12 13:48:16 [INFO] signed certificate with serial number 623257900327570025845323882529030636259183373984

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6d:2b:d9:d0:59:de:3b:8d:3e:67:11:54:d4:90:68:ea:05:c3:2e:a0
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:43:00 2020 GMT
            Not After : Sep 10 13:43:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:c5:fc:1f:b4:60:9d:56:2f:69:49:86:56:73:45:
                    48:1a:a2:39:cb:92:c6:af:bb:56:d0:55:2e:27:bf:
                    e1:7e:87:97:ac:cc:fb:3c:c8:05:ce:40:6f:a1:3e:
                    df:91:13:39:43:0b:8d:22:44:ba:05:cc:3b:af:1b:
                    08:26:1a:a8:e9
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
                1B:69:CA:02:72:C1:B9:23:AC:F9:02:03:67:B0:D3:ED:B8:D5:AD:F0
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:ab:58:e7:ee:8d:ee:67:57:ed:01:cc:12:b6:
         03:1e:6a:9c:67:3f:9c:f0:9f:d1:6d:e6:3a:f3:7d:5a:42:56:
         ae:02:20:55:cc:87:20:ca:80:99:d8:6f:5e:cd:6a:01:80:2b:
         f7:f1:1a:66:2d:c1:14:72:e2:c7:29:e8:4b:1a:7a:c9:94

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/centminmod.com.p12 -inkey /etc/cfssl/peercerts/centminmod.com-key.pem -in /etc/cfssl/peercerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "623257900327570025845323882529030636259183373984",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T13:43:00Z",
  "not_after": "2030-09-10T13:43:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "1B:69:CA:02:72:C1:B9:23:AC:F9:02:03:67:B0:D3:ED:B8:D5:AD:F0",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICYDCCAgagAwIBAgIUbSvZ0FneO40+ZxFU1JBo6gXDLqAwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzNDMwMFoXDTMwMDkxMDEzNDMwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMX8\nH7RgnVYvaUmGVnNFSBqiOcuSxq+7VtBVLie/4X6Hl6zM+zzIBc5Ab6E+35ETOUML\njSJEugXMO68bCCYaqOmjga0wgaowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG\nCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQbacoC\ncsG5I6z5AgNnsNPtuNWt8DAfBgNVHSMEGDAWgBQgKcMr7F1AjG8wregAhVwvoR63\n6zArBgNVHREEJDAigg5jZW50bWlubW9kLmNvbYIQKi5jZW50bWlubW9kLmNvbTAK\nBggqhkjOPQQDAgNIADBFAiEAq1jn7o3uZ1ftAcwStgMeapxnP5zwn9Ft5jrzfVpC\nVq4CIFXMhyDKgJnYb17NagGAK/fxGmYtwRRy4scp6EsaesmU\n-----END CERTIFICATE-----\n"
}
```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
* peer key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
* peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -cn peer.centminmod.com -hostname peer.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem peer.centminmod.com.csr.json > peer.centminmod.com.json
2020/09/12 13:48:43 [INFO] generate received request
2020/09/12 13:48:43 [INFO] received CSR
2020/09/12 13:48:43 [INFO] generating key: ecdsa-256
2020/09/12 13:48:43 [INFO] encoded CSR
2020/09/12 13:48:43 [INFO] signed certificate with serial number 249012604233642552998969942113808891314214540991

cfssljson -f peer.centminmod.com.json -bare peer.centminmod.com


openssl x509 -in peer.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2b:9e:1c:81:e6:85:ff:50:98:80:08:92:66:f8:ee:68:42:8c:16:bf
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:44:00 2020 GMT
            Not After : Sep 10 13:44:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:87:de:a0:4e:57:3b:ee:fe:14:d1:75:18:37:02:
                    be:35:cb:47:88:e7:6d:30:e4:4e:fc:a8:50:8d:3a:
                    b0:98:fc:7d:ab:f1:43:27:b7:48:7a:54:83:4b:6f:
                    64:ab:8c:06:a7:e3:84:3b:c4:47:a8:61:c0:dd:81:
                    68:5b:e7:ec:a0
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
                79:F3:A4:02:4C:78:9E:93:A0:80:72:20:C6:9D:A9:26:B8:E3:25:94
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:74:f2:fb:2c:0f:4a:63:71:cd:c1:a6:79:38:12:
         4e:fc:80:e1:f3:e8:f4:65:fb:ef:54:63:ef:28:ce:fb:c2:e7:
         02:21:00:a2:1b:90:f7:cc:67:7d:44:0b:25:c6:f6:36:ad:bb:
         74:d3:01:c4:34:c1:9c:00:66:98:0e:ba:b8:b9:28:e4:ad

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/peer.centminmod.com.p12 -inkey /etc/cfssl/peercerts/peer.centminmod.com-key.pem -in /etc/cfssl/peercerts/peer.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
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
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "249012604233642552998969942113808891314214540991",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-12T13:44:00Z",
  "not_after": "2030-09-10T13:44:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "79:F3:A4:02:4C:78:9E:93:A0:80:72:20:C6:9D:A9:26:B8:E3:25:94",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWDCCAf6gAwIBAgIUK54cgeaF/1CYgAiSZvjuaEKMFr8wCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzNDQwMFoXDTMwMDkxMDEzNDQwMFowUDELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRwwGgYD\nVQQDExNwZWVyLmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEh96gTlc77v4U0XUYNwK+NctHiOdtMORO/KhQjTqwmPx9q/FDJ7dIelSDS29k\nq4wGp+OEO8RHqGHA3YFoW+fsoKOBoDCBnTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\nBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE\nFHnzpAJMeJ6ToIByIMadqSa44yWUMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACF\nXC+hHrfrMB4GA1UdEQQXMBWCE3BlZXIuY2VudG1pbm1vZC5jb20wCgYIKoZIzj0E\nAwIDSAAwRQIgdPL7LA9KY3HNwaZ5OBJO/IDh8+j0ZfvvVGPvKM77wucCIQCiG5D3\nzGd9RAslxvY2rbt00wHENMGcAGaYDrq4uSjkrQ==\n-----END CERTIFICATE-----\n"
}
```