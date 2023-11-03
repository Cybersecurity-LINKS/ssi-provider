The new options that `s_client` and `s_server` provide are the following:
- `-did`: endpoint's DID
- `-did_key`: file containing the endpoint's DID private key.
- `-did_methods`: list of DID methods supported by the client.
- `-vc`: expects a file that contains the endpoint's VC.
- `-VCIfile`: expects a file containing the list of VC issuers trusted by the client. 

`clnt-vc` and `srvr-vc` scripts simulate a VC authenticated handshake.  
`clnt-did` and `srvr-did` scripts simulate a DID authenticated handshake.