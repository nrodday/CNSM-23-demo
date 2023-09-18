#BGPsec-IO Configuration file. Auto generated by bgpsecio V0.2.1.10

ski_file    = "{LOCAL}/opt/bgp-srx-examples/bgpsec-keys/ski-list.txt";
ski_key_loc = "{LOCAL}/opt/bgp-srx-examples/bgpsec-keys/";

preload_eckey = false;

# Choose from the following types "BGP", "CAPI", "GEN-B", and "GEN-C"
mode = "BGP";
# Maximum combined number of updates to process. Script 0 for MAX INT
max = 0;

# Allow to force the usage of the flag for extended length being set. 
only_extended_length = true;

# bin = "<binary input file>";
# out = "<binary output file>";
# Append data to the out file.
appendOut = "false";

# Allow to specify a configuration file for srx-crypto-api,If this is not specified,
# the default srx-crypto-api configuration (determined by the API) will be used.
#capi_cfg = "<configuration file>";

# Multiple sessions possible (at a later time)
session = (
  {
    asn        = {BIO_ASN};
    bgp_ident  = "{PEER_IP}";
    hold_timer = 180;

    # Allows to specify specific session IP.
    # If not specified, the bgp_ident value is used!
    #local_addr = "10.0.1.64";

    # Allows to specify next hop address. If not,
    # specified the bgp identifier is used instead!
    #next_hop_ipv4 = "10.0.1.64";
    # Required for sending IPv6 updates.
    #next_hop_ipv6 = "0:0:0:0:0:ffff:a00:140";

    peer_asn   = 65000;
    peer_ip    = "{PEER_IP}";
    peer_port  = 179;

    # Run forever or until the peer shuts down.
    disconnect = 0;

    # Enable BGP convergence measurement framework.
    convergence = false;

    # Allow to enable/disable extended message capability.
    ext_msg_cap = true;
    # Allow to enable/disable liberal behavior when 
    # receiving extended message capability.
    ext_msg_liberal = true;
    # Overwrite draft / RFC specification and force.
    # sending extended message regardless if negotiated or not.
    #ext_msg_force = true;

    # Configure BGP capabilities.
    #cap_as4 = true;

    # Configure BGPSEC capabilities.
    bgpsec_v4_snd = false;
    bgpsec_v4_rcv = false;
    bgpsec_v6_snd = false;
    bgpsec_v6_rcv = false;

    # Updates for this session only
    # (path prefix B4 specifies BGP-4 only update!)
    # <prefix>[,[B4]? ([{]?<asn>[p<repitition>][ ]*[}]?)+[I|V|N]?]
    #   <asn>        := [0-9]+[.[0-9]+]?>
    #   <repetition> := [0-9]+
    # Updates are allowed to have one AS_SET { 65010 65020 } in the path
    update = ( 
             );

    # Enable/Disable adding global updates to this session.
    incl_global_updates = true;

    # Allow prefix packing for BGP-4 scripted updates
    # where ever possible.
    prefixPacking = false;

    algo_id = 1;

    # Choose from the following signature modes (CAPI|BIO|BIO-K1|BIO-K2)
    signature_generation = "BIO";

    #In case the signature generation does fail, the
    #following settings are possible (DROP| FAKE| BGP4)
    null_signature_mode = "FAKE";
    fake_signature      = "1BADBEEFDEADFEED" "2BADBEEFDEADFEED"
                          "3BADBEEFDEADFEED" "4BADBEEFDEADFEED"
                          "5BADBEEFDEADFEED" "6BADBEEFDEADFEED"
                          "7BADBEEFDEADFEED" "8BADBEEFDEADFEED"
                          "ABADBEEFFACE";
    fake_ski            = "0102030405060708" "090A0B0C0D0E0F10"
                          "11121314";

    # Allow printout of send and received BGP/BGPsec traffic.
    printOnSend    = false;
    # Or more detailed as a filter
    #printOnSend = {
    #  open         = true;
    #  update       = true;
    #  keepalive    = true;
    #  notification = true;
    #  unknown      = true;
    #};

    printOnReceive    = false;
    # Or more detailed as a filter
    #printOnReceive = {
    #  open         = true;
    #  update       = true;
    #  keepalive    = true;
    #  notification = true;
    #  unknown      = true;
    #};

    #printSimple     = false;

    printPollLoop  = false;

    # For CAPI Mode.
    printOnInvalid = false;

  }
# Currently multi sessions are not supported, that is
# the reason the following section is commented out!
#  ,{
      # Here script another session
      # Minimum configuration
      # asn = 65000;
      # bgp_ident = 10.0.1.64;
      # peer_asn = 65005;
      # peer_ip = 10.0.1.32;
#  }

);

# global updates for all sessions
# <prefix>[,[B4]? ([{]?<asn>[p<repitition>][ ]*[}]?)+[I|V|N]?]
#   <asn>        := [0-9]+[.[0-9]+]?>
#   <repitition> := [0-9]+
# Updates are allowed to have one AS_SET { 65010 65020 } in the path
update = ( 
         );
