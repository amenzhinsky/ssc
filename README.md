# ssc

Self-signed certificates generator.

## Installation

```bash
export PATH=$(go env GOPATH)/bin:$PATH
go get -u github.com/amenzhinsky/ssc
```

## Usage

Generate root certificate:

```bash
ssc -common-name="Root CA" -ca -keyout=ca.key.pem -certout=ca.crt.pem
```

Generate and validate intermediate CA:

```bash
ssc -common-name="Intermediate CA" -ca -keyout=intermediate.key.pem -certout=intermediate.crt.pem
openssl verify -CAfile=ca.crt.pem intermediate.crt.pem
```

Generate server certificate with [Subject Alternative Names](https://tools.ietf.org/html/rfc5280#section-4.2.1.6) and [Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12) flags signed by the previously generated intermediate CA:

```bash
ssc -common-name=server -san-dns=example.com -eku-server -certout=server.crt.pem -keyout=server.key.out -cacert=intermediate.crt.pem -cakey=intermediate.key.pem

openssl verify -verbose -CAfile=<(cat ca.crt.pem intermediate.crt.pem) server.crt.pem

cat intermediate.crt.pem server.crt.pem > full.crt.pem
openssl verify -verbose -CAfile=ca.crt.pem full.crt.pem 
```

You can use `openssl` to inspect generated certificates:

```bash
openssl x509 -text -noout -in server.crt.pem
```
