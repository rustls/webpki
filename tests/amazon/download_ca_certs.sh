#!/bin/bash

# download roots
curl -O https://www.amazontrust.com/repository/AmazonRootCA1.cer
curl -O https://www.amazontrust.com/repository/AmazonRootCA2.cer
curl -O https://www.amazontrust.com/repository/AmazonRootCA3.cer
curl -O https://www.amazontrust.com/repository/AmazonRootCA4.cer
curl -O https://www.amazontrust.com/repository/SFSRootCAG2.cer

# download roots as intermediates (from G2 root)
curl -O http://crt.rootca1.amazontrust.com/rootca1.cer
curl -O http://crt.rootca2.amazontrust.com/rootca2.cer
curl -O http://crt.rootca3.amazontrust.com/rootca3.cer
curl -O http://crt.rootca4.amazontrust.com/rootca4.cer

# download root CRLs
curl -O http://crl.rootca1.amazontrust.com/rootca1.crl
curl -O http://crl.rootca2.amazontrust.com/rootca2.crl
curl -O http://crl.rootca3.amazontrust.com/rootca3.crl
curl -O http://crl.rootca4.amazontrust.com/rootca4.crl

# Intermediates for CA1
curl -O http://crt.r2m01.amazontrust.com/r2m01.cer
curl -O http://crt.r2m02.amazontrust.com/r2m02.cer
curl -O http://crt.r2m03.amazontrust.com/r2m03.cer
curl -O http://crt.r2m04.amazontrust.com/r2m04.cer

# CRLs for intermediates for CA1
curl -O http://crl.r2m01.amazontrust.com/r2m01.crl
curl -O http://crl.r2m02.amazontrust.com/r2m02.crl
curl -O http://crl.r2m03.amazontrust.com/r2m03.crl
curl -O http://crl.r2m04.amazontrust.com/r2m04.crl

# Intermediates for CA2
curl -O http://crt.r4m01.amazontrust.com/r4m01.cer
curl -O http://crt.r4m02.amazontrust.com/r4m02.cer
curl -O http://crt.r4m03.amazontrust.com/r4m03.cer
curl -O http://crt.r4m04.amazontrust.com/r4m04.cer

# CRLs for Intermediates for CA2
curl -O http://crl.r4m01.amazontrust.com/r4m01.crl
curl -O http://crl.r4m02.amazontrust.com/r4m02.crl
curl -O http://crl.r4m03.amazontrust.com/r4m03.crl
curl -O http://crl.r4m04.amazontrust.com/r4m04.crl

# Intermediates for CA3
curl -O http://crt.e2m01.amazontrust.com/e2m01.cer
curl -O http://crt.e2m02.amazontrust.com/e2m02.cer
curl -O http://crt.e2m03.amazontrust.com/e2m03.cer
curl -O http://crt.e2m04.amazontrust.com/e2m04.cer

# CRLs for Intermediates for CA3
curl -O http://crl.e2m01.amazontrust.com/e2m01.crl
curl -O http://crl.e2m02.amazontrust.com/e2m02.crl
curl -O http://crl.e2m03.amazontrust.com/e2m03.crl
curl -O http://crl.e2m04.amazontrust.com/e2m04.crl

# Intermediates for CA4
curl -O http://crt.e3m01.amazontrust.com/e3m01.cer
curl -O http://crt.e3m02.amazontrust.com/e3m02.cer
curl -O http://crt.e3m03.amazontrust.com/e3m03.cer
curl -O http://crt.e3m04.amazontrust.com/e3m04.cer

# CRLs for Intermediates for CA4
curl -O http://crl.e3m01.amazontrust.com/e3m01.crl
curl -O http://crl.e3m02.amazontrust.com/e3m02.crl
curl -O http://crl.e3m03.amazontrust.com/e3m03.crl
curl -O http://crl.e3m04.amazontrust.com/e3m04.crl
