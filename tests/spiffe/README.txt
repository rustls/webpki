An SVID is a structured x509 certificate that follows the SPIFFE x509-SVID
format available at:

	https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md

For these tests, an SVID was created following the example from: 

	https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/

```
git clone https://github.com/spiffe/spire
cd spire
go build ./cmd/spire-server
go build ./cmd/spire-agent
./spire-server run -config conf/server/server.conf&
./spire-server healthcheck
./spire-server token generate -spiffeID spiffe://example.org/myagent
./spire-agent run -config conf/agent/agent.conf -joinToken <token_string> &
./spire-agent healthcheck
./spire-server entry create -parentID spiffe://example.org/myagent \
    -spiffeID spiffe://example.org/myservice -selector unix:uid:$(id -u)
mkdir /tmp/spiffe-svid
./spire-agent api fetch x509 -write /tmp/spiffe-svid
```


The above commands generate three files
* `bundle.0.pem` contains the set of root CAs trusted by your current trust domain
* `svid.0.pem` contains the SVID (x509 certificate) and its associated chain of
  trust. In this case, the intermediate agent's own identity.
* `svid.0.key` contains the private key of the the SVID for `myservice`

You can inspect the above using

```
openssl x509 -in bundle.0.pem -text
openssl x509 -in svid.0.pem -text # only shows the first certificate, which is the SVID
```

For webpki tests, I split the svid.0.pem into two separate files:

 * inter.0.pem
 * service.0.pem

I did the above manually since it's a one-off.

```
openssl x509 -in bundle.0.pem -out bundle.0.der -outform DER 
openssl x509 -in inter.0.pem -out inter.0.der -outform DER 
openssl x509 -in service.0.pem -out service.0.der -outform DER 
```

I then cleaned up the directory a bit by deleting the intermediate inter.0.pem
and service.0.pem since these are preserved in the included svid.0.pem.
