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
2020/09/11 13:15:24 [INFO] generating a new CA key and certificate from CSR
2020/09/11 13:15:24 [INFO] generate received request
2020/09/11 13:15:24 [INFO] received CSR
2020/09/11 13:15:24 [INFO] generating key: ecdsa-256
2020/09/11 13:15:24 [INFO] encoded CSR
2020/09/11 13:15:24 [INFO] signed certificate with serial number 438415250363664973500164721566815087306398358475
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4c:cb:38:41:4a:c4:ef:c1:d7:3e:30:d8:3b:73:a6:37:ca:85:db:cb
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 11 13:10:00 2020 GMT
            Not After : Sep  9 13:10:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:8f:a8:e0:95:c5:bd:e1:77:fa:ad:a7:a7:62:34:
                    83:9a:66:2b:50:01:c9:9c:20:2d:eb:1f:21:7c:23:
                    16:e2:de:39:c2:a9:f6:04:3a:36:68:84:bd:d0:16:
                    d4:33:a9:bf:9b:16:c8:3b:85:7d:11:8d:7a:c2:be:
                    9c:45:5e:3a:9b
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                63:85:05:BB:E9:55:BE:02:CB:CB:05:94:0F:E9:92:A0:97:29:94:7D
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:55:0e:23:c5:b2:ec:21:09:98:9f:12:d5:bc:f4:
         b9:58:b7:67:61:cc:89:dd:f0:fe:e9:5a:71:c0:91:fd:ba:57:
         02:21:00:f6:07:42:b2:82:01:ee:54:9c:82:83:f9:7a:b2:70:
         3c:9d:ac:69:43:6d:00:b4:b8:78:40:a0:6d:96:40:ef:03

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca key: /etc/cfssl/centminmod.com-ca-key.pem
ca csr: /etc/cfssl/centminmod.com-ca.csr
ca csr profile: /etc/cfssl/centminmod.com-ca.csr.json
ca profile: /etc/cfssl/profile.json
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600
2020/09/11 13:41:34 [INFO] generate received request
2020/09/11 13:41:34 [INFO] received CSR
2020/09/11 13:41:34 [INFO] generating key: ecdsa-256
2020/09/11 13:41:34 [INFO] encoded CSR
2020/09/11 13:41:34 [INFO] signed certificate with serial number 429435777256240190076053754479796902057694302971
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4b:38:90:f5:83:a4:01:da:e3:91:27:8b:0c:c2:68:25:a2:01:92:fb
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 11 13:37:00 2020 GMT
            Not After : Sep  9 13:37:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:bf:da:df:d0:fd:3e:bd:a6:51:a5:b2:f4:81:58:
                    40:a8:d4:54:39:65:54:6b:68:0a:95:22:da:07:81:
                    ff:a6:72:cb:81:13:1c:e7:61:67:b6:b0:c8:66:86:
                    bc:5f:f5:2b:4c:0f:75:af:21:b4:f4:8a:78:4f:48:
                    9d:cb:9a:cc:0d
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
                99:63:1E:51:3E:C8:D7:8D:26:1E:39:B9:3D:D8:FF:28:D0:5E:34:6B
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:f4:b5:a2:25:4c:f5:2d:b2:ca:79:62:e8:bb:
         81:cb:29:93:fc:1e:a0:0b:3d:f0:b6:9f:9d:b9:98:73:af:b7:
         59:02:21:00:d7:97:44:93:e8:1b:f3:50:c7:e1:f2:b5:44:f3:
         8f:9a:25:d6:5f:63:70:d1:b0:74:b2:dd:bb:da:e4:66:f9:8c

ca cert: /etc/cfssl/servercerts/centminmod.com.pem
ca key: /etc/cfssl/servercerts/centminmod.com-key.pem
ca csr: /etc/cfssl/servercerts/centminmod.com.csr
ca csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server
2020/09/11 13:36:59 [INFO] generate received request
2020/09/11 13:36:59 [INFO] received CSR
2020/09/11 13:36:59 [INFO] generating key: ecdsa-256
2020/09/11 13:36:59 [INFO] encoded CSR
2020/09/11 13:36:59 [INFO] signed certificate with serial number 10021354647919696435755925556586656783817241313
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:c1:5f:82:70:c7:46:5c:7f:27:9e:90:52:99:6b:e5:94:cf:f2:e1
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 11 13:32:00 2020 GMT
            Not After : Sep  9 13:32:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:4b:6a:3d:66:96:2a:73:c2:8d:06:cb:67:ff:17:
                    a5:d7:03:c4:e5:3b:8c:2f:15:dc:ab:cf:78:ef:3a:
                    ba:a6:55:52:bc:07:ca:0c:78:ff:d5:1b:2f:31:85:
                    22:06:f3:68:f3:be:09:a6:19:b0:6d:56:4e:06:61:
                    c9:a7:53:52:aa
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
                8B:22:B1:17:64:61:BF:8E:C4:AA:D4:D9:A3:F2:C3:BA:BB:9B:43:58
            X509v3 Authority Key Identifier: 
                keyid:63:85:05:BB:E9:55:BE:02:CB:CB:05:94:0F:E9:92:A0:97:29:94:7D

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:bc:cd:6e:60:8b:52:69:c0:f6:0a:9e:3e:1e:
         5b:9b:75:b4:26:5f:b3:78:59:85:59:f5:80:67:f9:83:47:2e:
         71:02:20:3c:03:fa:d8:b9:e5:cd:00:e6:ea:c7:bf:c6:68:9a:
         25:65:01:ce:6b:7a:07:b8:14:cf:ba:b1:00:01:8f:c6:07

ca cert: /etc/cfssl/servercerts/server.centminmod.com.pem
ca key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
ca csr: /etc/cfssl/servercerts/server.centminmod.com.csr
ca csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600      
2020/09/11 13:42:56 [INFO] generate received request
2020/09/11 13:42:56 [INFO] received CSR
2020/09/11 13:42:56 [INFO] generating key: ecdsa-256
2020/09/11 13:42:56 [INFO] encoded CSR
2020/09/11 13:42:56 [INFO] signed certificate with serial number 465174207563424785619528441456858737913911763284
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            51:7b:22:04:d8:fc:52:0b:a5:21:33:27:4b:53:0e:63:2d:9e:e1:54
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 11 13:38:00 2020 GMT
            Not After : Sep  9 13:38:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:30:e0:58:6a:7c:ae:0b:a5:8b:81:1d:83:8e:06:
                    21:bd:82:9d:d6:58:30:23:20:fa:c4:0f:93:71:37:
                    7b:02:c9:ae:da:e4:a8:ee:cf:2c:43:23:7a:dd:ea:
                    74:ba:ad:59:f5:a0:2e:a0:9b:6a:04:a7:40:a9:0e:
                    87:30:27:b0:b0
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
                75:70:6F:38:8B:41:A1:11:6F:9A:CB:20:C2:C5:65:B9:6B:FF:CB:02
            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:4f:64:7f:82:ca:d5:dd:11:23:3f:50:8f:6a:c6:
         a5:4d:5f:c4:a0:78:da:74:8d:20:95:08:54:76:14:aa:de:5e:
         02:21:00:96:9e:de:55:ec:b8:f3:36:96:ff:dd:04:50:8f:86:
         a5:51:5b:b5:47:b7:43:8f:79:cb:a8:8e:ca:0a:59:64:d6

ca cert: /etc/cfssl/clientcerts/centminmod.com.pem
ca key: /etc/cfssl/clientcerts/centminmod.com-key.pem
ca csr: /etc/cfssl/clientcerts/centminmod.com.csr
ca csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client
2020/09/11 13:38:30 [INFO] generate received request
2020/09/11 13:38:30 [INFO] received CSR
2020/09/11 13:38:30 [INFO] generating key: ecdsa-256
2020/09/11 13:38:30 [INFO] encoded CSR
2020/09/11 13:38:30 [INFO] signed certificate with serial number 568047955268108991163828788750663213452762172124
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            63:80:26:ba:08:d7:38:08:ff:82:c6:f9:01:36:4a:26:f5:9e:4a:dc
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 11 13:34:00 2020 GMT
            Not After : Sep  9 13:34:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:d0:b6:15:cb:b1:4e:b7:d4:13:c9:31:47:f4:d1:
                    9c:bb:36:dd:03:04:2a:d0:f4:49:1f:79:0b:e4:a8:
                    69:0c:4b:3c:89:fa:90:ea:15:71:4c:da:ef:7d:a3:
                    62:a6:e6:27:3d:95:12:a5:50:bd:cc:7f:de:67:e5:
                    a0:ae:fb:50:6e
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
                ED:5B:25:08:35:32:9F:31:54:4C:BD:53:56:E6:EF:A9:B8:F0:36:4F
            X509v3 Authority Key Identifier: 
                keyid:63:85:05:BB:E9:55:BE:02:CB:CB:05:94:0F:E9:92:A0:97:29:94:7D

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:0f:a6:6c:da:a5:ff:10:02:dc:94:cf:92:62:28:
         d0:f9:cb:0a:95:fe:73:88:51:6a:8f:3c:4a:fd:6e:73:ed:6b:
         02:20:42:76:31:47:68:4d:7d:96:93:75:80:58:10:7c:db:58:
         ae:17:0e:03:79:0f:71:ba:fa:14:32:2d:8c:09:62:6d

ca cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
ca key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
ca csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
ca csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json
```