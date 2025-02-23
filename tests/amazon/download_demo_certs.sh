#!/bin/bash

DOMAINS="valid.rootca1.demo.amazontrust.com
valid.rootca2.demo.amazontrust.com
valid.rootca3.demo.amazontrust.com
valid.rootca4.demo.amazontrust.com
revoked.rootca1.demo.amazontrust.com
revoked.rootca2.demo.amazontrust.com
revoked.rootca3.demo.amazontrust.com
revoked.rootca4.demo.amazontrust.com
expired.rootca1.demo.amazontrust.com
expired.rootca2.demo.amazontrust.com
expired.rootca3.demo.amazontrust.com
expired.rootca4.demo.amazontrust.com"


for domain in $DOMAINS; do
    openssl s_client -showcerts -connect "${domain}:443" -servername "$domain" -verify_quiet <<<"Q" | openssl x509 -outform DER > "${domain}.cer"
done
