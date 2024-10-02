## Daedalus x509 hierarchy

<img src="img/01_tree.png?raw=true" alt="tree" width="453" height="300"/>

x509 certificate package used to test the fetching of missing certificates in the chain.

### [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) HTTP/FTP
* caIssuers
	* **end entity** or **CA certificates** (excluding root)
		* single [DER encoded](https://datatracker.ietf.org/doc/html/rfc2585#section-3) certificate
			* `.cer`
				application/pkix-cert
		* CMS "[certs-only](https://datatracker.ietf.org/doc/html/rfc2797#section-2.2)" message
			* `.p7c`
				application/pkcs7-mime

### [Subject Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2) HTTP/FTP
* caRepository
	* **CA certificates**
		* single DER encoded certificate
			* `.cer`
				application/pkix-cert
		* CMS "certs-only" message
			* `.p7c`
				application/pkcs7-mime

## Steps to reproduce

* edit `Daedalus_hierarchy.sh` script and change the address of your local server: `website_ca="http://localhost:1180/${test_directory}"`
* run the script: `./daedalus_hierarchy.sh`
* 2 folders will be created:
	* `p7c_tests_xxxxx` - copy to the root directory of the local server
	* `IMPORT_THIS_xxxxx` - contains files for testing the download of missing certificates via http.

In Windows, when you open `IMPORT_THIS_xxxxx/cert_G1.der.cer` file, the system retrieves the missing certificates and displays the following chain:

<img src="img/windows_preview.png?raw=true" alt="ms" width="565" height="300"/>

(“A” root CA certificate intentionally missing)

There are 3 generated packages on this page:

* `daedalus_462d7.tar.gz`
* `daedalus_4341c.tar.gz`
* `daedalus_04297.tar.gz`

## Technical details

### AIA (Authority Information Access)

The extension included in the certificate is used to download missing certificates and build the chain up (forward direction). We start with the USER “G” and end with the “trusted” root certificate “A”.

(arrows should be drawn in reverse)

#### G1

<img src="img/02_g1.png?raw=true" alt="g1" width="332" height="300"/>

G1←F1←E1←D2←C2←B1

#### G2

<img src="img/03_g2.png?raw=true" alt="g2" width="379" height="300"/>

G2←

#### G3

<img src="img/04_g3.png?raw=true" alt="g3" width="367" height="300"/>

G3←

#### G4

<img src="img/05_g4.png?raw=true" alt="g4" width="355" height="300"/>

G4←F3←E2

#### certificates obtained so far

<img src="img/06_stage1_end.png?raw=true" alt="stage1" width="387" height="300"/>

#### G5

<img src="img/07_g5.png?raw=true" alt="g5" width="351" height="300"/>

G5←F4←

#### G6

<img src="img/08_g6.png?raw=true" alt="g6" width="304" height="300"/>

G6←F5←E3←

#### G7

<img src="img/09_g7.png?raw=true" alt="g7" width="336" height="300"/>

G7←F6←E4←D3←C3←B2←A

#### summary

<img src="img/10_summary.png?raw=true" alt="summary" width="375" height="300"/>

### SIA (Subject Information Access)

The extension included in the certificate is used to retrieve missing certificates and build the chain down (in reverse). We start with the “trusted” root certificate A and go all the way to the final USER G.

<img src="img/11_sia.png?raw=true" alt="sia" width="423" height="300"/>

### links

* [sleevi_ no1](https://medium.com/@sleevi_/path-building-vs-path-verifying-the-chain-of-pain-9fbab861d7d6)
* [sleevi_ no2](https://medium.com/@sleevi_/path-building-vs-path-verifying-implementation-showdown-39a9272b2820)
* [rfc4158](https://datatracker.ietf.org/doc/html/rfc4158)
* [openssl-verification-options](https://docs.openssl.org/master/man1/openssl-verification-options/)
* [Updated for Red Hat Certificate System 10.4](https://docs.redhat.com/en/documentation/red_hat_certificate_system/10/html-single/planning_installation_and_deployment_guide/index)
* [SecurityEngineering/Certificate Verification](https://wiki.mozilla.org/SecurityEngineering/Certificate_Verification)
* [Bridge Certification Authorities](https://web.archive.org/web/20060223104224/https://csrc.nist.gov/pki/documents/B2B-article.pdf)

##### ms stuff

* [Troubleshooting Certificate Status and Revocation](https://learn.microsoft.com/en-us/previous-versions/tn-archive/cc700843(v=technet.10))
* [Planning and Implementing Cross-Certification and Qualified Subordination](https://www.sysadmins.lv/dl/32.aspx)
* [Certification Authority Guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831574(v=ws.11))
* [Securing PKI: Planning Certificate Algorithms and Usages](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786428(v=ws.11))
* [How CA Certificates Work](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc737264(v=ws.10))
