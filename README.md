# CNSM-23-demo
Artifacts of the CNSM 2023 demo paper

## Setup 
```bash
cd AS-Cones/
./buildBGP-SRx.sh BIO
./buildBGP-SRx.sh SRxSnP
cd ../GoBGPSRx 
go install ./...
```

## Demo Setup 
```bash
# Terminal 1: Start RPKI-harness
cd path/to/AS-Cones/local-6.2.0/bin
./rpkirtr_svr -f [...]

# Terminal 2: Start the SRx-Server
cd path/to/AS-Cones/local-6.2.0/bin
./srx_server -f [...]

# Terminal 1: Check if the SRx-Server is connected to the RPKI
> clients 

# Terminal 3: Start GoBGPSRx daemon 
cd GO_PATH/bin/
sudo ./gobgpd -p -f [...] --log-level=debug 

# Terminal 4: Generate Input with BGPsecIO
cd path/to/AS-Cones/local-6.2.0/bin
./bgpsecio -f [...]
```
