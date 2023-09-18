/* BGP message definition header.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGPD_H
#define _QUAGGA_BGPD_H

/* For union sockunion.  */
#include "sockunion.h"
// NIST: Added config.h to reduce invalid errors reported in IDE's
#include "config.h"

#ifdef USE_SRX
#include <srx/srx_api.h>
#include <srx/srxcryptoapi.h>
#include "bgp_info_hash.h"

// @TODO: REMOVE THIS MACRO
#define SRX_PRINT_HEX(DATA, DLEN)    \
{                                    \
  int sph_idx = 0;                   \
  while (sph_idx < DLEN)             \
  {                                  \
    if (sph_idx % 16 == 0)           \
    {                                \
      printf ("\n");                 \
    }                                \
    else if (sph_idx % 8 == 0)       \
    {                                \
      printf (" ");                  \
    }                                \
    printf(" %02X", DATA[sph_idx]);  \
    sph_idx++;                       \
  }                                  \
  printf ("\n");                     \
}

/** For now two
 * different private keys seem to be enough.*/
#define SRX_MAX_PRIVKEYS 2

#define SRX_VTY_HLP_STR         "SRx configuration setting\n"
/*SRX_VTY_EVAL_XXXXX - TAKE CARE THAT ONLY THE FIRST THREE LETTERS ARE COMPARED!!*/
#define SRX_VTY_EVAL_ORIGIN       "origin"
#define SRX_VTY_EVAL_BGPSEC       "bgpsec"
#define SRX_VTY_EVAL_ASPA         "aspa"
#define SRX_VTY_EVAL_ASCONE       "ascone"
// The following is to be used in combination with SRX_VTY_EVAL_BGPSEC
#define SRX_VTY_EVAL_BGPSEC_DISTR "distributed"

#define SRX_VTY_PARAM_CONNECT_SRV  0
#define SRX_VTY_PARAM_CONNECT_PORT 1
#define SRX_VTY_CMD_CONNECT_SHORT "srx connect"
#define SRX_VTY_HLP_CONNECT_SHORT SRX_VTY_HLP_STR \
                                  "Connect the router with SRx server\n"
#define SRX_VTY_CMD_CONNECT   SRX_VTY_CMD_CONNECT_SHORT " .LINE <0-65535>"
#define SRX_VTY_OUT_CONNECT   "srx connect %s %d%s"
#define SRX_VTY_HLP_CONNECT   SRX_VTY_HLP_CONNECT_SHORT \
                              "Specifies SRx server host name or IP address\n" \
                              "Specifies SRx server port\n"

#define SRX_VTY_CMD_DISCONNECT  "srx disconnect"
#define SRX_VTY_HLP_DISCONNECT  SRX_VTY_HLP_STR \
                                "Disconnect from the SRx server\n"

#define SRX_VTY_CMD_DISPLAY     "srx display"
#define SRX_VTY_OUT_DISPLAY     "srx display%s"
#define SRX_VTY_HLP_DISPLAY     SRX_VTY_HLP_STR \
                                "Add SRx related output to the \"show\"" \
                                " commands\n"
#define SRX_VTY_HLP_DISPLAY_NO  SRX_VTY_HLP_STR \
                                "Hide SRx related output from the \"show\"" \
                                " commands\n"

#define SRX_VTY_CMD_EVALUATE    "srx evaluation (" SRX_VTY_EVAL_ORIGIN \
                                                 "|" SRX_VTY_EVAL_BGPSEC \
                                                 "|" SRX_VTY_EVAL_ASPA \
                                                 "|" SRX_VTY_EVAL_ASCONE ")"
#define SRX_VTY_OUT_EVALUATE    "srx evaluation %s%s"
#define SRX_VTY_HLP_EVALUATE    SRX_VTY_HLP_STR \
                                "Activate the policy processing\n" \
                                "Perform prefix origin validation using " \
                                  "ROAs\n" \
                                "Perform BGPsec path validation\n" \
                                "Perform ASPA validation\n" \
                                "Perform ASCONE validation"
#define SRX_VTY_CMD_NO_EVALUATE "no " SRX_VTY_CMD_EVALUATE
#define SRX_VTY_HLP_NO_EVALUATE  NO_STR SRX_VTY_HLP_STR \
                                "Deactivate the policy processing\n" \
                                "Disable prefix origin validation\n" \
                                "Disable BGPsec path validation\n" \
                                "Disable ASPA validation\n" \
                                "Disable ASCONE validation"                                

#define SRX_VTY_CMD_EVAL_WITHSRX "srx evaluation " SRX_VTY_EVAL_BGPSEC \
                                 " " SRX_VTY_EVAL_BGPSEC_DISTR
#define SRX_VTY_OUT_EVAL_WITHSRX "srx evaluation " SRX_VTY_EVAL_BGPSEC \
                                 " " SRX_VTY_EVAL_BGPSEC_DISTR "%s"
#define SRX_VTY_HLP_EVAL_WITHSRX SRX_VTY_HLP_STR \
                            "Activate the policy processing\n" \
                            "Perform BGPsec path validation\n" \
                            "Perform BGPsec path validation using srx-server.\n"

#define SRX_VTY_CMD_KEEPWINDOW_SHORT "srx keep-window"
#define SRX_VTY_CMD_KEEPWINDOW  SRX_VTY_CMD_KEEPWINDOW_SHORT " <0-65535>"
#define SRX_VTY_HLP_KEEPWINDOW  SRX_VTY_HLP_STR \
                                "Configure amount of time in seconds the SRx is" \
                                " requested to hold information after it "\
                                " is deleted!\n" \
                                "Time in seconds \'0\' disables this feature!\n"

//The short version is not a stand alone command, it is needed for a vtty output
#define SRX_VTY_CMD_SET_SERVER_SHORT "srx set-server"
#define SRX_VTY_CMD_SET_SERVER  SRX_VTY_CMD_SET_SERVER_SHORT " .LINE <0-65535>"
#define SRX_VTY_HLP_SET_SERVER  SRX_VTY_HLP_STR \
                                "Set the SRx server connection parameters\n"

#define SRX_VTY_CMD_PROXYID "srx set-proxy-id A.B.C.D"
#define SRX_VTY_HLP_PROXYID SRX_VTY_HLP_STR \
                            "Configure the proxy id. This is the id used to " \
                            "connect to the srx-server. By default the proxy " \
                            "is the same as the BGP router id. The id is " \
                            "specified a 4 byte unsigned integer specified " \
                            "in IPv4 format.\n"

#define SRX_VTY_CMD_SHOW_CONFIG "show srx-config"
#define SRX_VTY_HLP_SHOW_CONFIG SHOW_STR "SRx-BGP Router configuration\n"

// DEFAULT VALIDATION RESULT PARAMETER
#define SRX_VTY_PARAM_ORIGIN_VALUE 0
#define SRX_VTY_PARAM_BGPSEC_VALUE   1
#define SRX_VTY_PARAM_ASPA_VALUE   2
#define SRX_VTY_PARAM_ASCONE_VALUE   3

#define SRX_VTY_PARAM_BGPSEC_MIN_ALGOID 1
#define SRX_VTY_PARAM_BGPSEC_MAX_ALGOID 254

// DEFAULT VALIDATION RESULT FOR ORIGIN VALIDATION
#define SRX_VTY_CMD_CONF_DEF_ROA_RES "srx set-origin-value " \
                                 "(valid|notfound|invalid|undefined)"
#define SRX_VTY_HLP_CONF_DEF_ROA_RES SRX_VTY_HLP_STR \
                         "Configure the default result value for origin " \
                         "validation\n" \
                         "The origin validation default value is 'valid'\n" \
                         "The origin validation default value is 'notfound'\n" \
                         "The origin validation default value is 'invalid'\n" \
                         "The origin validation default value is 'undefined'\n"

// DEFAULT VALIDATION RESULT FOR BGPSEC VALIDATION
#define SRX_VTY_CMD_CONF_DEF_BGPSEC_RES "srx set-bgpsec-value " \
                                  "(valid|invalid|undefined)"
#define SRX_VTY_HLP_CONF_DEF_BGPSEC_RES SRX_VTY_HLP_STR \
                     "Configure the default result value for bgpsec path " \
                     "validation\n" \
                     "The bgpsec path validation default value is 'valid'\n" \
                     "The bgpsec path validation default value is 'invalid'\n" \
                     "The bgpsec path validation default value is 'undefined'\n"

#define SRX_VTY_CMD_CONF_DEF_ASPA_RES "srx set-aspa-value " \
                                "(valid|unknown|invalid|unverifiable|undefined)"
#define SRX_VTY_HLP_CONF_DEF_ASPA_RES SRX_VTY_HLP_STR \
                       "Configure the default result value for aspa " \
                       "validation\n" \
                       "The aspa validation default value is 'valid'\n" \
                       "The aspa validation default value is 'unknown'\n" \
                       "The aspa validation default value is 'invalid'\n" \
                       "The aspa validation default value is 'unverifiable'\n" \
                       "The aspa validation default value is 'undefined'\n"

#define SRX_VTY_CMD_CONF_DEF_ASCONE_RES "srx set-ascone-value " \
                                "(valid|unknown|invalid|unverifiable|undefined)"
#define SRX_VTY_HLP_CONF_DEF_ASCONE_RES SRX_VTY_HLP_STR \
                       "Configure the default result value for ascone " \
                       "validation\n" \
                       "The ascone validation default value is 'valid'\n" \
                       "The ascone validation default value is 'unknown'\n" \
                       "The ascone validation default value is 'invalid'\n" \
                       "The ascone validation default value is 'unverifiable'\n" \
                       "The ascone validation default value is 'undefined'\n"

// APPLY POLICY CHANGE
#define SRX_VTY_CMD_APPLY_POLICY "srx apply-policy"
#define SRX_VTY_HLP_APPLY_POLICY SRX_VTY_HLP_STR \
                                 "Apply SRx policy changes to all updates in" \
                                 " the RIB.\n"

//@CHECL I believe this can be deleted.
#define SRX_VTY_HLP_ORIGIN  "(" SRX_VTY_EVAL_ORIGIN ") "

// POLICY IGNORE 
#define SRX_VTY_CMD_POL  "srx policy "
#define SRX_VTY_HLP_POLICY  SRX_VTY_HLP_STR \
                            "Set policies depending on validation results\n"
#define SRX_VTY_NO_CMD_POL  "no srx policy "
#define SRX_VTY_NO_HLP_POLICY  NO_STR \
                               SRX_VTY_HLP_STR \
                            "Remove validation dependent policies\n"

// IGNORE FOR ROA RESULT
#define SRX_VTY_CMD_POL_ROA_IGNORE  SRX_VTY_CMD_POL  "origin ignore " \
                                    "(notfound|invalid|undefined)\n"
#define SRX_VTY_HLP_POL_ROA_IHLPR   "Ignore route with validation result "
#define SRX_VTY_HLP_POL_ROA_IGNORE  SRX_VTY_HLP_POLICY \
                                      "For origin validation\n" \
                                      "Ignore route\n" \
                                      SRX_VTY_HLP_POL_ROA_IHLPR "'notfound'\n" \
                                      SRX_VTY_HLP_POL_ROA_IHLPR "'invalid'\n" \
                                      SRX_VTY_HLP_POL_ROA_IHLPR "'undefined'\n"

#define SRX_VTY_NO_CMD_POL_ROA_IGNORE  SRX_VTY_NO_CMD_POL  "origin ignore " \
                                       "(notfound|invalid|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ROA_IHLPR   "Disable ignore route with validation " \
                                         "result "
#define SRX_VTY_NO_HLP_POL_ROA_IGNORE  SRX_VTY_NO_HLP_POLICY \
                                  "Disable policy for origin validation\n" \
                                  "Disable ignore policy for origin validation\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_IHLPR "'notfound'\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_IHLPR "'invalid'\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_IHLPR "'undefined'\n"

// IGNORE FPR BGPSEC RESULT
#define SRX_VTY_CMD_POL_BGPSEC_IGNORE  SRX_VTY_CMD_POL  "bgpsec ignore " \
                                       "(invalid|undefined)\n"
#define SRX_VTY_HLP_POL_BGPSEC_IHLPR   "Ignore route with validation result "
#define SRX_VTY_HLP_POL_BGPSEC_IGNORE  SRX_VTY_HLP_POLICY \
                                    "For bgpsec validation\n" \
                                    "Ignore route\n" \
                                    SRX_VTY_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                                    SRX_VTY_HLP_POL_BGPSEC_IHLPR "'undefined'\n"

#define SRX_VTY_NO_CMD_POL_BGPSEC_IGNORE  SRX_VTY_NO_CMD_POL  "bgpsec ignore " \
                                          "(invalid|undefined)\n"
#define SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "Disable ignore route with " \
                                        "validation result "
#define SRX_VTY_NO_HLP_POL_BGPSEC_IGNORE  SRX_VTY_NO_HLP_POLICY \
                               "Disable policy for bgpsec validation\n" \
                               "Disable ignore policy for bgpsec validation\n" \
                               SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                               SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'undefined'\n"


// IGNORE FPR ASPA RESULT
#define SRX_VTY_CMD_POL_ASPA_IGNORE  SRX_VTY_CMD_POL  "aspa ignore " \
                                     "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_HLP_POL_ASPA_IHLPR   "Ignore route with validation result "
#define SRX_VTY_HLP_POL_ASPA_IGNORE  SRX_VTY_HLP_POLICY \
                               "For aspa validation\n" \
                               "Ignore route\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'unknown'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'unverifiable'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'undefined'\n"

#define SRX_VTY_NO_CMD_POL_ASPA_IGNORE  SRX_VTY_NO_CMD_POL  "aspa ignore " \
                                    "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ASPA_IHLPR  "Disable ignore route with validation " \
                                       "result "
#define SRX_VTY_NO_HLP_POL_ASPA_IGNORE  SRX_VTY_NO_HLP_POLICY \
                            "Disable policy for aspa validation\n" \
                            "Disable ignore policy for aspa validation\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'unknown'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'unverifiable'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'undefined'\n"


// IGNORE FPR ASCONE RESULT
#define SRX_VTY_CMD_POL_ASCONE_IGNORE  SRX_VTY_CMD_POL  "ascone ignore " \
                                     "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_HLP_POL_ASCONE_IHLPR   "Ignore route with validation result "
#define SRX_VTY_HLP_POL_ASCONE_IGNORE  SRX_VTY_HLP_POLICY \
                               "For ascone validation\n" \
                               "Ignore route\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'unknown'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'unverifiable'\n" \
                               SRX_VTY_HLP_POL_BGPSEC_IHLPR "'undefined'\n"

#define SRX_VTY_NO_CMD_POL_ASCONE_IGNORE  SRX_VTY_NO_CMD_POL  "ascone ignore " \
                                    "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ASCONE_IHLPR  "Disable ignore route with validation " \
                                       "result "
#define SRX_VTY_NO_HLP_POL_ASCONE_IGNORE  SRX_VTY_NO_HLP_POLICY \
                            "Disable policy for ascone validation\n" \
                            "Disable ignore policy for ascone validation\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'unknown'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'invalid'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'unverifiable'\n" \
                            SRX_VTY_NO_HLP_POL_BGPSEC_IHLPR "'undefined'\n"


// LOCAL PREF FOR ROA
#define SRX_VTY_CMD_POL_ROA_LOCP  SRX_VTY_CMD_POL  "origin local-preference " \
                                         "(valid|notfound|invalid|undefined) " \
                                         "(add|subtract) <0-4294967295>\n"

#define SRX_VTY_HLP_POL_ROA_LHLPR   "Modify local preference of route with " \
                                      "origin validation result "
#define SRX_VTY_HLP_POL_ROA_LOCP    SRX_VTY_HLP_POLICY \
                                    "For origin validation\n" \
                                    "Modify local preference\n" \
                                    SRX_VTY_HLP_POL_ROA_LHLPR "'valid'\n" \
                                    SRX_VTY_HLP_POL_ROA_LHLPR "'notfound'\n" \
                                    SRX_VTY_HLP_POL_ROA_LHLPR "'invalid'\n" \
                                    SRX_VTY_HLP_POL_ROA_LHLPR "'undefined'\n" \
                                    "Increase the local preference\n" \
                                    "Decrease the local preferecne\n" \
                                    "The value by which the local preference " \
                                       "will be modified.\n"
                                         
#define SRX_VTY_NO_CMD_POL_ROA_LOCP SRX_VTY_NO_CMD_POL "origin local-preference " \
                                          "(valid|notfound|invalid|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ROA_LHLPR  "Disable local preference manipulation " \
                                      "for route with orign validation result "
#define SRX_VTY_NO_HLP_POL_ROA_LOCP  SRX_VTY_NO_HLP_POLICY \
                                  "Disable policy for origin validation\n" \
                                  "Disable local preference manipulation\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_LHLPR "'valid'\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_LHLPR "'notfound'\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_LHLPR "'invalid'\n" \
                                  SRX_VTY_NO_HLP_POL_ROA_LHLPR "'undefined'\n"

// LOCAL PREF FOR BGPSEC
#define SRX_VTY_CMD_POL_BGPSEC_LOCP SRX_VTY_CMD_POL "bgpsec local-preference " \
                                               "(valid|invalid|undefined) " \
                                               "(add|subtract) <0-4294967295>\n"

#define SRX_VTY_HLP_POL_BGPSEC_LHLPR  "Modify local preference of route with " \
                                         "bgpsec validation result "
#define SRX_VTY_HLP_POL_BGPSEC_LOCP SRX_VTY_HLP_POLICY \
                                  "For bgpsec validation\n" \
                                  "Modify local preference\n" \
                                  SRX_VTY_HLP_POL_BGPSEC_LHLPR "'valid'\n" \
                                  SRX_VTY_HLP_POL_BGPSEC_LHLPR "'invalid'\n" \
                                  SRX_VTY_HLP_POL_BGPSEC_LHLPR "'undefined'\n" \
                                  "Increase the local preference\n" \
                                  "Decrease the local preferecne\n" \
                                  "The value by which the local preference " \
                                     "will be modified.\n"
                                         
#define SRX_VTY_NO_CMD_POL_BGPSEC_LOCP SRX_VTY_NO_CMD_POL "bgpsec " \
                                                "local-preference " \
                                                "(valid|invalid|undefined)\n"
#define SRX_VTY_NO_HLP_POL_BGPSEC_LHLPR  "Disable local preference " \
                                         "manipulation for route with bgpsec " \
                                         "validation result "
#define SRX_VTY_NO_HLP_POL_BGPSEC_LOCP  SRX_VTY_NO_HLP_POLICY \
                                 "Disable policy for bgpsec validation\n" \
                                 "Disable local preference manipulation\n" \
                                 SRX_VTY_NO_HLP_POL_BGPSEC_LHLPR "'valid'\n" \
                                 SRX_VTY_NO_HLP_POL_BGPSEC_LHLPR "'invalid'\n" \
                                 SRX_VTY_NO_HLP_POL_BGPSEC_LHLPR "'undefined'\n"

// LOCAL PREF FOR ASPA
#define SRX_VTY_CMD_POL_ASPA_LOCP SRX_VTY_CMD_POL  "aspa local-preference " \
                             "(valid|unknown|invalid|unverifiable|undefined) " \
                             "(add|subtract) <0-4294967295>\n"

#define SRX_VTY_HLP_POL_ASPA_LHLPR "Modify local preference of route with " \
                                      "aspa validation result "
#define SRX_VTY_HLP_POL_ASPA_LOCP  SRX_VTY_HLP_POLICY \
                                 "For aspa validation\n" \
                                 "Modify local preference\n" \
                                 SRX_VTY_HLP_POL_ASPA_LHLPR "'valid'\n" \
                                 SRX_VTY_HLP_POL_ASPA_LHLPR "'unknown'\n" \
                                 SRX_VTY_HLP_POL_ASPA_LHLPR "'invalid'\n" \
                                 SRX_VTY_HLP_POL_ASPA_LHLPR "'unverifiable'\n" \
                                 SRX_VTY_HLP_POL_ASPA_LHLPR "'undefined'\n" \
                                 "Increase the local preference\n" \
                                 "Decrease the local preferecne\n" \
                                 "The value by which the local preference " \
                                    "will be modified.\n"
                                         
#define SRX_VTY_NO_CMD_POL_ASPA_LOCP SRX_VTY_NO_CMD_POL "aspa local-preference " \
                                    "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ASPA_LHLPR  "Disable local preference manipulation " \
                                      "for route with aspa validation result "
#define SRX_VTY_NO_HLP_POL_ASPA_LOCP  SRX_VTY_NO_HLP_POLICY \
                              "Disable policy for aspa validation\n" \
                              "Disable local preference manipulation\n" \
                              SRX_VTY_NO_HLP_POL_ASPA_LHLPR "'valid'\n" \
                              SRX_VTY_NO_HLP_POL_ASPA_LHLPR "'unknown'\n" \
                              SRX_VTY_NO_HLP_POL_ASPA_LHLPR "'invalid'\n" \
                              SRX_VTY_NO_HLP_POL_ASPA_LHLPR "'unverifiable'\n" \
                              SRX_VTY_NO_HLP_POL_ASPA_LHLPR "'undefined'\n"

// LOCAL PREF FOR ASCONE
#define SRX_VTY_CMD_POL_ASCONE_LOCP SRX_VTY_CMD_POL  "ascone local-preference " \
                             "(valid|unknown|invalid|unverifiable|undefined) " \
                             "(add|subtract) <0-4294967295>\n"

#define SRX_VTY_HLP_POL_ASCONE_LHLPR "Modify local preference of route with " \
                                      "ascone validation result "
#define SRX_VTY_HLP_POL_ASCONE_LOCP  SRX_VTY_HLP_POLICY \
                                 "For ascone validation\n" \
                                 "Modify local preference\n" \
                                 SRX_VTY_HLP_POL_ASCONE_LHLPR "'valid'\n" \
                                 SRX_VTY_HLP_POL_ASCONE_LHLPR "'unknown'\n" \
                                 SRX_VTY_HLP_POL_ASCONE_LHLPR "'invalid'\n" \
                                 SRX_VTY_HLP_POL_ASCONE_LHLPR "'unverifiable'\n" \
                                 SRX_VTY_HLP_POL_ASCONE_LHLPR "'undefined'\n" \
                                 "Increase the local preference\n" \
                                 "Decrease the local preferecne\n" \
                                 "The value by which the local preference " \
                                    "will be modified.\n"
                                         
#define SRX_VTY_NO_CMD_POL_ASCONE_LOCP SRX_VTY_NO_CMD_POL "ascone local-preference " \
                                    "(unknown|invalid|unverifiable|undefined)\n"
#define SRX_VTY_NO_HLP_POL_ASCONE_LHLPR  "Disable local preference manipulation " \
                                      "for route with ascone validation result "
#define SRX_VTY_NO_HLP_POL_ASCONE_LOCP  SRX_VTY_NO_HLP_POLICY \
                              "Disable policy for ascone validation\n" \
                              "Disable local preference manipulation\n" \
                              SRX_VTY_NO_HLP_POL_ASCONE_LHLPR "'valid'\n" \
                              SRX_VTY_NO_HLP_POL_ASCONE_LHLPR "'unknown'\n" \
                              SRX_VTY_NO_HLP_POL_ASCONE_LHLPR "'invalid'\n" \
                              SRX_VTY_NO_HLP_POL_ASCONE_LHLPR "'unverifiable'\n" \
                              SRX_VTY_NO_HLP_POL_ASCONE_LHLPR "'undefined'\n"

// USE OF COMMUNITY STRING
#define SRX_VTY_CMD_EXT_CSTR "srx extcommunity <0-255>"
#define SRX_VTY_HLP_EXT_CSTR SRX_VTY_HLP_STR "Configure community string for" \
                              " validation result transmission\n" \
                             "The sub code of the extended community.\n"

#define SRX_VTY_CMD_EXT_CSTR_EBGP SRX_VTY_CMD_EXT_CSTR " (include_ebgp|only_ibgp)"
#define SRX_VTY_HLP_EXT_CSTR_EBGP SRX_VTY_HLP_EXT_CSTR \
                                  "Include eBGP peers (optional)\n" \
                                  "Only iBGP peers - also used to turn off eBGP peers\n"

#define SRX_VTY_CMD_NO_EXT_CSTR "no srx extcommunity"
#define SRX_VTY_HLP_NO_EXT_CSTR  NO_STR SRX_VTY_HLP_STR \
                                "Deactivate the extended community validation" \
                                 " result transfer.\n"

// BGPSEC KEY MANAGEMENT
#define SRX_VTY_HLP_BGPSEC "BGPSEC specific configuration\n"

#define SRX_VTY_CMD_BGPSEC_SKI_PRNT "srx bgpsec ski (0|1) <1-254>"
#define SRX_VTY_CMD_BGPSEC_SKI SRX_VTY_CMD_BGPSEC_SKI_PRNT " WORD"
#define SRX_VTY_OUT_BGPSEC_SKI "srx bgpsec ski %u %s%s"
#define SRX_VTY_HLP_BGPSEC_SKI SRX_VTY_HLP_STR SRX_VTY_HLP_BGPSEC \
                              "Configures the SKI for the private key!\n" \
                              "Set the algorithm ID of the key \n" \
                              "The SKI, a 20 byte value as 40 byte HEX string of the SKI"

#define SRX_VTY_CMD_BGPSEC_ACTIVE_SKI "srx bgpsec active (0|1)"
#define SRX_VTY_OUT_BGPSEC_ACTIVE_SKI "srx bgpsec active %u%s"
#define SRX_VTY_HLP_BGPSEC_ACTIVE_SKI SRX_VTY_HLP_STR SRX_VTY_HLP_BGPSEC \
                                      "Configure which key is active"

#define SRX_VTY_CMD_BGPSEC_REGISTER_P_KEYS "srx bgpsec register keys"
#define SRX_VTY_HLP_BGPSEC_REGISTER_P_KEYS SRX_VTY_HLP_STR SRX_VTY_HLP_BGPSEC \
                          "This command will attempt to register the current " \
                          "keys. This might be required if a previous " \
                          "registration failed!\n"

// DEPRECATED AND REMOVED KEY COMMANDS
#define SRX_VTY_HLP_BGPSEC_DEP "Please use the replacement 'srx bgpsec ...'\n"
#define SRX_VTY_CMD_BGPSEC_DEP_SKI_PRNT "bgpsec ski"
#define SRX_VTY_CMD_BGPSEC_DEP_SKI SRX_VTY_CMD_BGPSEC_DEP_SKI_PRNT " WORD"
#define SRX_VTY_HLP_BGPSEC_DEP_SKI SRX_VTY_HLP_BGPSEC_DEP \
                                   "This command is deprecated! " \
                                   "Use '" SRX_VTY_CMD_BGPSEC_SKI_PRNT \
                                   " <ski>' instead!\n"

#define SRX_VTY_CMD_BGPSEC_DEP_SIGN "bgpsec sign (key|id)"
#define SRX_VTY_HLP_BGPSEC_DEP_SIGN SRX_VTY_HLP_BGPSEC_DEP \
                                    "This command is removed!\n"

// BGPSEC NEIGHBOR COMMANDS
#define SRX_VTY_CMD_NEIGHBOR_BGPSEC NEIGHBOR_CMD2 "bgpsec "
#define SRX_VTY_HLP_NEIGHBOR_BGPSEC NEIGHBOR_STR NEIGHBOR_ADDR_STR2 \
                                    "Configure the bgpsec capability to the peer\n"

#define SRX_VTY_CMD_NEIGHBOR_BGPSEC_MODE SRX_VTY_CMD_NEIGHBOR_BGPSEC \
                                    "(snd|rec|both)"
//                                    "(snd|rec|both|migrate|route-server)"
#define SRX_VTY_HLP_NEIGHBOR_BGPSEC_MODE SRX_VTY_HLP_NEIGHBOR_BGPSEC \
                                    "Send BGPSEC but receive BGP4 only\n" \
                                    "Receive BGPSEC but send BGP4 only\n" \
                                    "Send BGPSEC and receive BGPSEC\n"
//                                    "Flag this peering session as a migration." \
//                                    " This will cause the pCount set to be 0.\n" \
//                                    "Flag that the peer is a route server and " \
//                                    "this peer is allowed to set its pcount to zero.\n"

#define SRX_VTY_CMD_NO_NEIGHBOR_BGPSEC_MODE NO_NEIGHBOR_CMD2 "bgpsec " \
                                    "(snd|rec|both)"
//                                    "(snd|rec|both|migrate|route-server)"
#define SRX_VTY_HLP_NO_NEIGHBOR_BGPSEC_MODE NO_STR SRX_VTY_HLP_NEIGHBOR_BGPSEC \
                                    "Send BGPSEC but receive BGP4 only\n" \
                                    "Receive BGPSEC but send BGP4 only\n" \
                                    "Send BGPSEC and receive BGPSEC\n"
//                                    "Remove the migration flag. This will remove" \
//                                      " the acceptance of received" \
//                                      " pcount=0 values of this peer and pcount" \
//                                      " will not be set while" \
//                                      " sending updates to this peer.\n" \
//                                    "Unflag that the peer as a route server and" \
//                                    " receiving pcount equals zero is not allowed.\n"


#define SRX_VTY_CMD_NEIGHBOR_AS_RELATIONSHIP NEIGHBOR_CMD2 "aspa (provider|customer|sibling|lateral)" 
#define SRX_VTY_HLP_NEIGHBOR_AS_RELATIONSHIP NEIGHBOR_STR NEIGHBOR_ADDR_STR2 \
                                    "Configure ASPA peering relationship\n" \
                                    "The peer is a topologically upstream neighbor (transit provider)\n" \
                                    "The peer is a topologically downstream (customer AS)\n" \
                                    "The peer is transit provider and transit customer.\n" \
                                    "The peering only includes prefixes of customers.\n"

#define SRX_VTY_CMD_NO_NEIGHBOR_AS_RELATIONSHIP NO_NEIGHBOR_CMD2 "aspa (provider|customer|sibling|lateral)" 
#define SRX_VTY_HLP_NO_NEIGHBOR_AS_RELATIONSHIP NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 \
                                    "Configure ASPA peering relationship\n" \
                                    "The peer is a topologically upstream neighbor (transit provider)\n" \
                                    "The peer is a topologically downstream (customer AS)\n" \
                                    "The peer is transit provider and transit customer.\n" \
                                    "The peering only includes prefixes of customers.\n"





#endif /* USE_SRX */

/* Typedef BGP specific types.  */
typedef u_int32_t as_t;
typedef u_int16_t as16_t; /* we may still encounter 16 Bit asnums */
typedef u_int16_t bgp_size_t;

/* BGP master for system wide configurations and variables.  */
struct bgp_master
{
  /* BGP instance list.  */
  struct list *bgp;

  /* BGP thread master.  */
  struct thread_master *master;

  /* work queues */
  struct work_queue *process_main_queue;
  struct work_queue *process_rsclient_queue;

  /* Listening sockets */
  struct list *listen_sockets;

  /* BGP port number.  */
  u_int16_t port;

  /* Listener address */
  char *address;

  /* BGP start time.  */
  time_t start_time;

  /* Various BGP global configuration.  */
  u_char options;
#define BGP_OPT_NO_FIB                   (1 << 0)
#define BGP_OPT_MULTIPLE_INSTANCE        (1 << 1)
#define BGP_OPT_CONFIG_CISCO             (1 << 2)
#define BGP_OPT_NO_LISTEN                (1 << 3)
};

#ifdef USE_SRX
/** Data stored in this structure defines how the local pref has to be
 * manipulated.
 */
struct srx_local_pref {
  // Indicates if this local pref manipulation is enables.
  bool enable;
  // indicates if the value is to be added or subtracted
  bool add;
  // The local pref value
  uint32_t value;
};
#endif /* USE_SRX */

/* BGP instance structure.  */
struct bgp
{
  /* AS number of this BGP instance.  */
  as_t as;

  /* Name of this BGP instance.  */
  char *name;

  /* Reference count to allow peer_delete to finish after bgp_delete */
  int lock;

  /* Self peer.  */
  struct peer *peer_self;

  /* BGP peer. */
  struct list *peer;

  /* BGP peer group.  */
  struct list *group;

  /* BGP route-server-clients. */
  struct list *rsclient;

  /* BGP configuration.  */
  u_int16_t config;
#define BGP_CONFIG_ROUTER_ID              (1 << 0)
#define BGP_CONFIG_CLUSTER_ID             (1 << 1)
#define BGP_CONFIG_CONFEDERATION          (1 << 2)
#ifdef USE_SRX
#define BGP_CONFIG_SRX                    (1 << 3)

  /* SRX Configuration */
  u_int16_t srx_config;
#define SRX_CONFIG_EVAL_ASPA       (1 << 0)
#define SRX_CONFIG_EVAL_ASCONE       (1 << 5)
#define SRX_CONFIG_EVAL_ORIGIN     (1 << 1)
// Below must be set in combination with VALORIGIN
#define SRX_CONFIG_EVAL_PATH       (1 << 2)
// This define specifies if the BGPsec evaluation needs to be done distributed 
// or locally
#define SRX_CONFIG_EVAL_PATH_DISTR (1 << 3)
#define SRX_CONFIG_DISPLAY_INFO    (1 << 4)
#endif /* USE_SRX */

  /* BGP router identifier.  */
  struct in_addr router_id;
  struct in_addr router_id_static;

  /* BGP route reflector cluster ID.  */
  struct in_addr cluster_id;

  /* BGP confederation information.  */
  as_t confed_id;
  as_t *confed_peers;
  int confed_peers_cnt;

  /* BGP flags. */
  u_int16_t flags;
#define BGP_FLAG_ALWAYS_COMPARE_MED       (1 << 0)
#define BGP_FLAG_DETERMINISTIC_MED        (1 << 1)
#define BGP_FLAG_MED_MISSING_AS_WORST     (1 << 2)
#define BGP_FLAG_MED_CONFED               (1 << 3)
#define BGP_FLAG_NO_DEFAULT_IPV4          (1 << 4)
#define BGP_FLAG_NO_CLIENT_TO_CLIENT      (1 << 5)
#define BGP_FLAG_ENFORCE_FIRST_AS         (1 << 6)
#define BGP_FLAG_COMPARE_ROUTER_ID        (1 << 7)
#define BGP_FLAG_ASPATH_IGNORE            (1 << 8)
#define BGP_FLAG_IMPORT_CHECK             (1 << 9)
#define BGP_FLAG_NO_FAST_EXT_FAILOVER     (1 << 10)
#define BGP_FLAG_LOG_NEIGHBOR_CHANGES     (1 << 11)
#define BGP_FLAG_GRACEFUL_RESTART         (1 << 12)
#define BGP_FLAG_ASPATH_CONFED            (1 << 13)

  /* BGP Per AF flags */
  u_int16_t af_flags[AFI_MAX][SAFI_MAX];
#define BGP_CONFIG_DAMPENING              (1 << 0)

  /* Static route configuration.  */
  struct bgp_table *route[AFI_MAX][SAFI_MAX];

  /* Aggregate address configuration.  */
  struct bgp_table *aggregate[AFI_MAX][SAFI_MAX];

  /* BGP routing information base.  */
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];

  /* BGP redistribute configuration. */
  u_char redist[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP redistribute metric configuration. */
  u_char redist_metric_flag[AFI_MAX][ZEBRA_ROUTE_MAX];
  u_int32_t redist_metric[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP redistribute route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP distance configuration.  */
  u_char distance_ebgp;
  u_char distance_ibgp;
  u_char distance_local;

  /* BGP default local-preference.  */
  u_int32_t default_local_pref;

  /* BGP default timer.  */
  u_int32_t default_holdtime;
  u_int32_t default_keepalive;

  /* BGP graceful restart */
  u_int32_t restart_time;
  u_int32_t stalepath_time;

  /* Maximum-paths configuration */
  struct bgp_maxpaths_cfg {
    u_int16_t maxpaths_ebgp;
    u_int16_t maxpaths_ibgp;
  } maxpaths[AFI_MAX][SAFI_MAX];

#ifdef USE_SRX
  /* Configuration */
  // All the default configuration is set in the method srx_set_default

  char *srx_host;
  int  srx_port;
#define SRX_HANDHAKE_TIMEOUT  30
#define SRX_KEEP_WINDOW      900

  // The timeout during the session establishment
  int  srx_handshakeTimeout;
  // Time in seconds the SRx server is requested to keep data after a delete
  int  srx_keepWindow;
  uint32_t srx_proxyID;
  
#define NUM_LOCPREF_TYPE   3
#define LOCPRF_TYPE_ROA    0
#define LOCPRF_TYPE_BGPSEC 1
#define LOCPRF_TYPE_ASPA   2
#define LOCPRF_TYPE_ASCONE 3

// This defines are used to parse through the type specific local preference 
// configuration array - The first set is the size of each array, the second 
// set specifies the location of the specific validation results in each array.
#define VAL_LOCPRF_CT_ROA       4
#define VAL_LOCPRF_CT_BGPSEC    3
#define VAL_LOCPRF_CT_ASPA      5
#define VAL_LOCPRF_CT_ASCONE    6

  // undefined, valid, invalid, notfound
  struct srx_local_pref srx_loc_pref_roa[VAL_LOCPRF_CT_ROA];    
  // undefined, valid, invalid 
  struct srx_local_pref srx_loc_pref_bgpsec[VAL_LOCPRF_CT_BGPSEC];
  // undefined, valid, invalid, unknown, unverifiable 
  struct srx_local_pref srx_loc_pref_aspa[VAL_LOCPRF_CT_ASPA];
  // undefined, valid, invalid, unknown, unverifiable 
  struct srx_local_pref srx_loc_pref_ascone[VAL_LOCPRF_CT_ASCONE];
  
#define VAL_LOCPRF_UNDEFINED    0
#define VAL_LOCPRF_VALID        1
#define VAL_LOCPRF_INVALID      2
#define VAL_LOCPRF_NOTFOUND     3
#define VAL_LOCPRF_UNKNOWN      3
#define VAL_LOCPRF_UNVERIFIABLE 4

  /** Contains the bit coded policy setting*/
  uint16_t srx_val_policy;
  
#define SRX_VAL_POLICY_ORIGIN_IGNORE_NOTFOUND      (1 << 0)
#define SRX_VAL_POLICY_ORIGIN_IGNORE_INVALID       (1 << 1)
#define SRX_VAL_POLICY_ORIGIN_IGNORE_UNDEFINED     (1 << 2)

#define SRX_VAL_POLICY_BGPSEC_IGNORE_INVALID    (1 << 3)
#define SRX_VAL_POLICY_BGPSEC_IGNORE_UNDEFINED  (1 << 4)

#define SRX_VAL_POLICY_ASPA_IGNORE_UNKNOWN      (1 << 5)
#define SRX_VAL_POLICY_ASPA_IGNORE_INVALID      (1 << 6)
#define SRX_VAL_POLICY_ASPA_IGNORE_UNVERIFIABLE (1 << 7)
#define SRX_VAL_POLICY_ASPA_IGNORE_UNDEFINED    (1 << 8)

#define SRX_VAL_POLICY_ASCONE_IGNORE_UNKNOWN      (1 << 9)
#define SRX_VAL_POLICY_ASCONE_IGNORE_INVALID      (1 << 10)
#define SRX_VAL_POLICY_ASCONE_IGNORE_UNVERIFIABLE (1 << 11)
#define SRX_VAL_POLICY_ASCONE_IGNORE_UNDEFINED    (1 << 12)
                                      
  uint16_t srx_default_roaVal;
  uint16_t srx_default_bgpsecVal;
  uint16_t srx_default_aspaVal;
  uint16_t srx_default_asconeVal;

  /* Instance variables */
  SRxProxy* srxProxy;
  /* The info hash for update id's */
  struct bgp_info_hash* info_uid_hash;
  /* The info hash for local id's */
  struct bgp_info_hash* info_lid_hash;
  /** The SRx CryptoAPI instance. Will be currently maintained as g_capi in
   * bgp_validate.c */
  SRxCryptoAPI* srxCAPI;

  /* The bgpsec private key array. */
  BGPSecKey srx_bgpsec_key[SRX_MAX_PRIVKEYS];
  /** The key to be used, 0..SRX_MAX_PRIVKEYS-1.*/
  u_int8_t  srx_bgpsec_active_key;

  /** Contains the information if extended community is used and the subcode*/
#define SRX_BGP_FLAG_ECOMMUNITY      (1 << 0)
#define SRX_BGP_FLAG_ECOMMUNITY_EBGP (1 << 1)
  u_int8_t srx_ecommunity_flags;
  u_int8_t srx_ecommunity_subcode;
#endif /* USE_SRX */
};

/* BGP peer-group support. */
struct peer_group
{
  /* Name of the peer-group. */
  char *name;

  /* Pointer to BGP.  */
  struct bgp *bgp;

  /* Peer-group client list. */
  struct list *peer;

  /* Peer-group config */
  struct peer *conf;
};

/* BGP Notify message format. */
struct bgp_notify
{
  u_char code;
  u_char subcode;
  char *data;
  bgp_size_t length;
};

/* Next hop self address. */
struct bgp_nexthop
{
  struct interface *ifp;
  struct in_addr v4;
#ifdef HAVE_IPV6
  struct in6_addr v6_global;
  struct in6_addr v6_local;
#endif /* HAVE_IPV6 */
};

/* BGP router distinguisher value.  */
#define BGP_RD_SIZE                8

struct bgp_rd
{
  u_char val[BGP_RD_SIZE];
};

#define RMAP_IN           0
#define RMAP_OUT        1
#define RMAP_IMPORT   2
#define RMAP_EXPORT   3
#define RMAP_MAX        4

/* BGP filter structure. */
struct bgp_filter
{
  /* Distribute-list.  */
  struct
  {
    char *name;
    struct access_list *alist;
  } dlist[FILTER_MAX];

  /* Prefix-list.  */
  struct
  {
    char *name;
    struct prefix_list *plist;
  } plist[FILTER_MAX];

  /* Filter-list.  */
  struct
  {
    char *name;
    struct as_list *aslist;
  } aslist[FILTER_MAX];

  /* Route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } map[RMAP_MAX];

  /* Unsuppress-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } usmap;
};

/* IBGP/EBGP identifier.  We also have a CONFED peer, which is to say,
   a peer who's AS is part of our Confederation.  */
typedef enum
{
  BGP_PEER_IBGP = 1,
  BGP_PEER_EBGP,
  BGP_PEER_INTERNAL,
  BGP_PEER_CONFED,
} bgp_peer_sort_t;

/* BGP neighbor structure. */
struct peer
{
  /* BGP structure.  */
  struct bgp *bgp;

  /* reference count, primarily to allow bgp_process'ing of route_node's
   * to be done after a struct peer is deleted.
   *
   * named 'lock' for hysterical reasons within Quagga.
   */
  int lock;

  /* BGP peer group.  */
  struct peer_group *group;
  u_char af_group[AFI_MAX][SAFI_MAX];

  /* Peer's remote AS number. */
  as_t as;

  /* Peer's local AS number. */
  as_t local_as;

  bgp_peer_sort_t sort;

  /* Peer's Change local AS number. */
  as_t change_local_as;

  /* Remote router ID. */
  struct in_addr remote_id;

  /* Local router ID. */
  struct in_addr local_id;

  /* Peer specific RIB when configured as route-server-client. */
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream_fifo *obuf;
  struct stream *work;

  /* Status of the peer. */
  int status;
  int ostatus;

  /* Peer index, used for dumping TABLE_DUMP_V2 format */
  uint16_t table_dump_index;

  /* Peer information */
  int fd;			/* File descriptor */
  int ttl;			/* TTL of TCP connection to the peer. */
  int gtsm_hops;		/* minimum hopcount to peer */
  char *desc;			/* Description of the peer. */
  unsigned short port;          /* Destination port for peer */
  char *host;			/* Printable address of the peer. */
  union sockunion su;		/* Sockunion address of the peer. */
  time_t uptime;		/* Last Up/Down time */
  time_t readtime;		/* Last read time */
  time_t resettime;		/* Last reset time */

  unsigned int ifindex;		/* ifindex of the BGP connection. */
  char *ifname;			/* bind interface name. */
  char *update_if;
  union sockunion *update_source;
  struct zlog *log;

  union sockunion *su_local;	/* Sockunion of local address.  */
  union sockunion *su_remote;	/* Sockunion of remote address.  */
  int shared_network;		/* Is this peer shared same network. */
  struct bgp_nexthop nexthop;	/* Nexthop */

  /* Peer address family configuration. */
  u_char afc[AFI_MAX][SAFI_MAX];
  u_char afc_nego[AFI_MAX][SAFI_MAX];
  u_char afc_adv[AFI_MAX][SAFI_MAX];
  u_char afc_recv[AFI_MAX][SAFI_MAX];

  /* Capability flags (reset in bgp_stop) */
  u_int16_t cap;
#define PEER_CAP_REFRESH_ADV                (1 << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_OLD_RCV            (1 << 1) /* refresh old received */
#define PEER_CAP_REFRESH_NEW_RCV            (1 << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV                (1 << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV                (1 << 4) /* dynamic received */
#define PEER_CAP_RESTART_ADV                (1 << 5) /* restart advertised */
#define PEER_CAP_RESTART_RCV                (1 << 6) /* restart received */
#define PEER_CAP_AS4_ADV                    (1 << 7) /* as4 advertised */
#define PEER_CAP_AS4_RCV                    (1 << 8) /* as4 received */
#ifdef USE_SRX
#define PEER_CAP_EXTENDED_MSG_SUPPORT       (1 << 13)/* extended message support*/
#define PEER_CAP_BGPSEC_ADV_SEND            (1 << 14)/* bgpsec advertised send capability */
#define PEER_CAP_BGPSEC_ADV                 (1 << 15)/* bgpsec advertised recv capability */
#endif

  /* Capability flags (reset in bgp_stop) */
  u_int16_t af_cap[AFI_MAX][SAFI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1 << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1 << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1 << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1 << 3) /* receive-mode received */
#define PEER_CAP_ORF_PREFIX_SM_OLD_RCV      (1 << 4) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_OLD_RCV      (1 << 5) /* receive-mode received */
#define PEER_CAP_RESTART_AF_RCV             (1 << 6) /* graceful restart afi/safi received */
#define PEER_CAP_RESTART_AF_PRESERVE_RCV    (1 << 7) /* graceful restart afi/safi F-bit received */

  /* Global configuration flags. */
  u_int32_t flags;
#define PEER_FLAG_PASSIVE                   (1 << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1 << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1 << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1 << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1 << 4) /* strict-match */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1 << 5) /* dynamic capability */
#define PEER_FLAG_DISABLE_CONNECTED_CHECK   (1 << 6) /* disable-connected-check */
#define PEER_FLAG_LOCAL_AS_NO_PREPEND       (1 << 7) /* local-as no-prepend */
#define PEER_FLAG_LOCAL_AS_REPLACE_AS       (1 << 8) /* local-as no-prepend replace-as */
#ifdef USE_SRX
#define PEER_FLAG_EXTENDED_MESSAGE_SUPPORT  (1 << 9) /* BGP-Extended Message Support */
#define PEER_FLAG_BGPSEC_MPE_IPV4           (1 << 10) /* mp extension for ipv4 */
// The next two flags allow pcount=0, both in receiving and migrate also in sending
#define PEER_FLAG_BGPSEC_MIGRATE            (1 << 11) /* enable migration mode with this peer */
#define PEER_FLAG_BGPSEC_ROUTE_SERVER       (1 << 12) /* the peer is a route server */
#define PEER_FLAG_EXTENDED_MESSAGE_LIBERAL  (1 << 13) /* BGP-Extended Message Support liberal */
#define PEER_FLAG_BGPSEC_CAPABILITY_RECV    (1 << 14)/* bgpsec capability - RECV */
#define PEER_FLAG_BGPSEC_CAPABILITY_SEND    (1 << 15)/* bgpsec capability - SEND */
#define PEER_FLAG_BGPSEC_CAPABILITY         (1 << 15)/* bgpsec capability - SEND */
#define PEER_FLAG_ASPA_RELATIONSHIP_PROV    (1 << 16)/* ASPA peer relationship provider */
#define PEER_FLAG_ASPA_RELATIONSHIP_CUST    (1 << 17)/* ASPA peer relationship customer */
#define PEER_FLAG_ASPA_RELATIONSHIP_SIBL    (1 << 18)/* ASPA peer relationship sibling */
#define PEER_FLAG_ASPA_RELATIONSHIP_LATL    (1 << 19)/* ASPA peer relationship lateral */
#define PEER_FLAG_ASCONE_RELATIONSHIP_PROV    (1 << 20)/* ASCONE peer relationship provider */
#define PEER_FLAG_ASCONE_RELATIONSHIP_CUST    (1 << 21)/* ASCONE peer relationship customer */
#define PEER_FLAG_ASCONE_RELATIONSHIP_SIBL    (1 << 22)/* ASCONE peer relationship sibling */
#define PEER_FLAG_ASCONE_RELATIONSHIP_LATL    (1 << 23)/* ASCONE peer relationship lateral */
#endif

  /* NSF mode (graceful restart) */
  u_char nsf[AFI_MAX][SAFI_MAX];

  /* Per AF configuration flags. */
  u_int32_t af_flags[AFI_MAX][SAFI_MAX];
#define PEER_FLAG_SEND_COMMUNITY            (1 << 0) /* send-community */
#define PEER_FLAG_SEND_EXT_COMMUNITY        (1 << 1) /* send-community ext. */
#define PEER_FLAG_NEXTHOP_SELF              (1 << 2) /* next-hop-self */
#define PEER_FLAG_REFLECTOR_CLIENT          (1 << 3) /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT            (1 << 4) /* route-server-client */
#define PEER_FLAG_SOFT_RECONFIG             (1 << 5) /* soft-reconfiguration */
#define PEER_FLAG_AS_PATH_UNCHANGED         (1 << 6) /* transparent-as */
#define PEER_FLAG_NEXTHOP_UNCHANGED         (1 << 7) /* transparent-next-hop */
#define PEER_FLAG_MED_UNCHANGED             (1 << 8) /* transparent-next-hop */
#define PEER_FLAG_DEFAULT_ORIGINATE         (1 << 9) /* default-originate */
#define PEER_FLAG_REMOVE_PRIVATE_AS         (1 << 10) /* remove-private-as */
#define PEER_FLAG_ALLOWAS_IN                (1 << 11) /* set allowas-in */
#define PEER_FLAG_ORF_PREFIX_SM             (1 << 12) /* orf capability send-mode */
#define PEER_FLAG_ORF_PREFIX_RM             (1 << 13) /* orf capability receive-mode */
#define PEER_FLAG_MAX_PREFIX                (1 << 14) /* maximum prefix */
#define PEER_FLAG_MAX_PREFIX_WARNING        (1 << 15) /* maximum prefix warning-only */
#define PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED   (1 << 16) /* leave link-local nexthop unchanged */

  /* MD5 password */
  char *password;

  /* default-originate route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } default_rmap[AFI_MAX][SAFI_MAX];

  /* Peer status flags. */
  u_int16_t sflags;
#define PEER_STATUS_ACCEPT_PEER	      (1 << 0) /* accept peer */
#define PEER_STATUS_PREFIX_OVERFLOW   (1 << 1) /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN   (1 << 2) /* capability open send */
#define PEER_STATUS_HAVE_ACCEPT       (1 << 3) /* accept peer's parent */
#define PEER_STATUS_GROUP             (1 << 4) /* peer-group conf */
#define PEER_STATUS_NSF_MODE          (1 << 5) /* NSF aware peer */
#define PEER_STATUS_NSF_WAIT          (1 << 6) /* wait comeback peer */

  /* Peer status af flags (reset in bgp_stop) */
  u_int16_t af_sflags[AFI_MAX][SAFI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND   (1 << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH  (1 << 1) /* wait refresh received peer */
#define PEER_STATUS_DEFAULT_ORIGINATE (1 << 2) /* default-originate peer */
#define PEER_STATUS_PREFIX_THRESHOLD  (1 << 3) /* exceed prefix-threshold */
#define PEER_STATUS_PREFIX_LIMIT      (1 << 4) /* exceed prefix-limit */
#define PEER_STATUS_EOR_SEND          (1 << 5) /* end-of-rib send to peer */
#define PEER_STATUS_EOR_RECEIVED      (1 << 6) /* end-of-rib received from peer */

  /* Default attribute value for the peer. */
  u_int32_t config;
#define PEER_CONFIG_WEIGHT            (1 << 0) /* Default weight. */
#define PEER_CONFIG_TIMER             (1 << 1) /* keepalive & holdtime */
#define PEER_CONFIG_CONNECT           (1 << 2) /* connect */
#define PEER_CONFIG_ROUTEADV          (1 << 3) /* route advertise */
  u_int32_t weight;
  u_int32_t holdtime;
  u_int32_t keepalive;
  u_int32_t connect;
  u_int32_t routeadv;

  /* Timer values. */
  u_int32_t v_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_asorig;
  u_int32_t v_routeadv;
  u_int32_t v_pmax_restart;
  u_int32_t v_gr_restart;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_asorig;
  struct thread *t_routeadv;
  struct thread *t_pmax_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;

  /* workqueues */
  struct work_queue *clear_node_queue;

  /* Statistics field */
  u_int32_t open_in;		/* Open message input count */
  u_int32_t open_out;		/* Open message output count */
  u_int32_t update_in;		/* Update message input count */
  u_int32_t update_out;		/* Update message ouput count */
  time_t update_time;		/* Update message received time. */
  u_int32_t keepalive_in;	/* Keepalive input count */
  u_int32_t keepalive_out;	/* Keepalive output count */
  u_int32_t notify_in;		/* Notify input count */
  u_int32_t notify_out;		/* Notify output count */
  u_int32_t refresh_in;		/* Route Refresh input count */
  u_int32_t refresh_out;	/* Route Refresh output count */
  u_int32_t dynamic_cap_in;	/* Dynamic Capability input count.  */
  u_int32_t dynamic_cap_out;	/* Dynamic Capability output count.  */

  /* BGP state count */
  u_int32_t established;	/* Established */
  u_int32_t dropped;		/* Dropped */

  /* Syncronization list and time.  */
  struct bgp_synchronize *sync[AFI_MAX][SAFI_MAX];
  time_t synctime;

  /* Send prefix count. */
  unsigned long scount[AFI_MAX][SAFI_MAX];

  /* Announcement attribute hash.  */
  struct hash *hash[AFI_MAX][SAFI_MAX];

  /* Notify data. */
  struct bgp_notify notify;

  /* Whole packet size to be read. */
  unsigned long packet_size;

  /* Filter structure. */
  struct bgp_filter filter[AFI_MAX][SAFI_MAX];

  /* ORF Prefix-list */
  struct prefix_list *orf_plist[AFI_MAX][SAFI_MAX];

#ifdef USE_SRX
  // Flag this peer to be migrated. In this case set the pCount to zero and
  // also allow this peer to set its pCount to zero.
  bool bgpsec_migrate;
#endif

  /* Prefix count. */
  unsigned long pcount[AFI_MAX][SAFI_MAX];

  /* Max prefix count. */
  unsigned long pmax[AFI_MAX][SAFI_MAX];
  u_char pmax_threshold[AFI_MAX][SAFI_MAX];
  u_int16_t pmax_restart[AFI_MAX][SAFI_MAX];
#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

  /* allowas-in. */
  char allowas_in[AFI_MAX][SAFI_MAX];

  /* peer reset cause */
  char last_reset;
#define PEER_DOWN_RID_CHANGE             1 /* bgp router-id command */
#define PEER_DOWN_REMOTE_AS_CHANGE       2 /* neighbor remote-as command */
#define PEER_DOWN_LOCAL_AS_CHANGE        3 /* neighbor local-as command */
#define PEER_DOWN_CLID_CHANGE            4 /* bgp cluster-id command */
#define PEER_DOWN_CONFED_ID_CHANGE       5 /* bgp confederation identifier command */
#define PEER_DOWN_CONFED_PEER_CHANGE     6 /* bgp confederation peer command */
#define PEER_DOWN_RR_CLIENT_CHANGE       7 /* neighbor route-reflector-client command */
#define PEER_DOWN_RS_CLIENT_CHANGE       8 /* neighbor route-server-client command */
#define PEER_DOWN_UPDATE_SOURCE_CHANGE   9 /* neighbor update-source command */
#define PEER_DOWN_AF_ACTIVATE           10 /* neighbor activate command */
#define PEER_DOWN_USER_SHUTDOWN         11 /* neighbor shutdown command */
#define PEER_DOWN_USER_RESET            12 /* clear ip bgp command */
#define PEER_DOWN_NOTIFY_RECEIVED       13 /* notification received */
#define PEER_DOWN_NOTIFY_SEND           14 /* notification send */
#define PEER_DOWN_CLOSE_SESSION         15 /* tcp session close */
#define PEER_DOWN_NEIGHBOR_DELETE       16 /* neighbor delete */
#define PEER_DOWN_RMAP_BIND             17 /* neighbor peer-group command */
#define PEER_DOWN_RMAP_UNBIND           18 /* no neighbor peer-group command */
#define PEER_DOWN_CAPABILITY_CHANGE     19 /* neighbor capability command */
#define PEER_DOWN_PASSIVE_CHANGE        20 /* neighbor passive command */
#define PEER_DOWN_MULTIHOP_CHANGE       21 /* neighbor multihop command */
#define PEER_DOWN_NSF_CLOSE_SESSION     22 /* NSF tcp session close */

  /* The kind of route-map Flags.*/
  u_char rmap_type;
#define PEER_RMAP_TYPE_IN             (1 << 0) /* neighbor route-map in */
#define PEER_RMAP_TYPE_OUT            (1 << 1) /* neighbor route-map out */
#define PEER_RMAP_TYPE_NETWORK        (1 << 2) /* network route-map */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1 << 3) /* redistribute route-map */
#define PEER_RMAP_TYPE_DEFAULT        (1 << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_NOSET          (1 << 5) /* not allow to set commands */
#define PEER_RMAP_TYPE_IMPORT         (1 << 6) /* neighbor route-map import */
#define PEER_RMAP_TYPE_EXPORT         (1 << 7) /* neighbor route-map export */
};

#define PEER_PASSWORD_MINLEN	(1)
#define PEER_PASSWORD_MAXLEN	(80)

/* This structure's member directly points incoming packet data
   stream. */
struct bgp_nlri
{
  /* AFI.  */
  afi_t afi;

  /* SAFI.  */
  safi_t safi;

  /* Pointer to NLRI byte stream.  */
  u_char *nlri;

  /* Length of whole NLRI.  */
  bgp_size_t length;
};

/* BGP versions.  */
#define BGP_VERSION_4		                 4

/* Default BGP port number.  */
#define BGP_PORT_DEFAULT                       179

/* BGP message header and packet size.  */
#define BGP_MARKER_SIZE		                16
#define BGP_HEADER_SIZE		                19
#define BGP_MAX_PACKET_SIZE                   4096
#ifdef USE_SRX
#define BGP_MAX_PACKET_SIZE_EXTENDED         65535
#endif

/* BGP minimum message size.  */
#define BGP_MSG_OPEN_MIN_SIZE                   (BGP_HEADER_SIZE + 10)
#define BGP_MSG_UPDATE_MIN_SIZE                 (BGP_HEADER_SIZE + 4)
#define BGP_MSG_NOTIFY_MIN_SIZE                 (BGP_HEADER_SIZE + 2)
#define BGP_MSG_KEEPALIVE_MIN_SIZE              (BGP_HEADER_SIZE + 0)
#define BGP_MSG_ROUTE_REFRESH_MIN_SIZE          (BGP_HEADER_SIZE + 4)
#define BGP_MSG_CAPABILITY_MIN_SIZE             (BGP_HEADER_SIZE + 3)

/* BGP message types.  */
#define	BGP_MSG_OPEN		                 1
#define	BGP_MSG_UPDATE		                 2
#define	BGP_MSG_NOTIFY		                 3
#define	BGP_MSG_KEEPALIVE	                 4
#define BGP_MSG_ROUTE_REFRESH_NEW                5
#define BGP_MSG_CAPABILITY                       6
#define BGP_MSG_ROUTE_REFRESH_OLD              128

/* BGP open optional parameter.  */
#define BGP_OPEN_OPT_AUTH                        1
#define BGP_OPEN_OPT_CAP                         2

/* BGP4 attribute type codes.  */
#define BGP_ATTR_ORIGIN                          1
#define BGP_ATTR_AS_PATH                         2
#define BGP_ATTR_NEXT_HOP                        3
#define BGP_ATTR_MULTI_EXIT_DISC                 4
#define BGP_ATTR_LOCAL_PREF                      5
#define BGP_ATTR_ATOMIC_AGGREGATE                6
#define BGP_ATTR_AGGREGATOR                      7
#define BGP_ATTR_COMMUNITIES                     8
#define BGP_ATTR_ORIGINATOR_ID                   9
#define BGP_ATTR_CLUSTER_LIST                   10
#define BGP_ATTR_DPA                            11
#define BGP_ATTR_ADVERTISER                     12
#define BGP_ATTR_RCID_PATH                      13
#define BGP_ATTR_MP_REACH_NLRI                  14
#define BGP_ATTR_MP_UNREACH_NLRI                15
#define BGP_ATTR_EXT_COMMUNITIES                16
#define BGP_ATTR_AS4_PATH                       17
#define BGP_ATTR_AS4_AGGREGATOR                 18
#define BGP_ATTR_AS_PATHLIMIT                   21
#if defined(USE_SRX) && !defined(BGP_ATTR_BGPSEC)
#define BGP_ATTR_BGPSEC                         33
#endif

/* BGP update origin.  */
#define BGP_ORIGIN_IGP                           0
#define BGP_ORIGIN_EGP                           1
#define BGP_ORIGIN_INCOMPLETE                    2

/* BGP notify message codes.  */
#define BGP_NOTIFY_HEADER_ERR                    1
#define BGP_NOTIFY_OPEN_ERR                      2
#define BGP_NOTIFY_UPDATE_ERR                    3
#define BGP_NOTIFY_HOLD_ERR                      4
#define BGP_NOTIFY_FSM_ERR                       5
#define BGP_NOTIFY_CEASE                         6
#define BGP_NOTIFY_CAPABILITY_ERR                7
#define BGP_NOTIFY_MAX	                         8

#define BGP_NOTIFY_SUBCODE_UNSPECIFIC            0

/* BGP_NOTIFY_HEADER_ERR sub codes.  */
#define BGP_NOTIFY_HEADER_NOT_SYNC               1
#define BGP_NOTIFY_HEADER_BAD_MESLEN             2
#define BGP_NOTIFY_HEADER_BAD_MESTYPE            3
#define BGP_NOTIFY_HEADER_MAX                    4

/* BGP_NOTIFY_OPEN_ERR sub codes.  */
#define BGP_NOTIFY_OPEN_UNSUP_VERSION            1
#define BGP_NOTIFY_OPEN_BAD_PEER_AS              2
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT            3
#define BGP_NOTIFY_OPEN_UNSUP_PARAM              4
#define BGP_NOTIFY_OPEN_AUTH_FAILURE             5
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME          6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL              7
#ifdef USE_SRX
#define BGP_NOTIFY_OPEN_UNSUP_BGPSEC             8
#endif
#define BGP_NOTIFY_OPEN_MAX                      9

/* BGP_NOTIFY_UPDATE_ERR sub codes.  */
#define BGP_NOTIFY_UPDATE_MAL_ATTR               1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR             2
#define BGP_NOTIFY_UPDATE_MISS_ATTR              3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR          4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR          5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN           6
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP          7
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP         8
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR           9
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK         10
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH           11
#define BGP_NOTIFY_UPDATE_MAX                   12

/* BGP_NOTIFY_CEASE sub codes (RFC 4486).  */
#define BGP_NOTIFY_CEASE_MAX_PREFIX              1
#define BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN          2
#define BGP_NOTIFY_CEASE_PEER_UNCONFIG           3
#define BGP_NOTIFY_CEASE_ADMIN_RESET             4
#define BGP_NOTIFY_CEASE_CONNECT_REJECT          5
#define BGP_NOTIFY_CEASE_CONFIG_CHANGE           6
#define BGP_NOTIFY_CEASE_COLLISION_RESOLUTION    7
#define BGP_NOTIFY_CEASE_OUT_OF_RESOURCE         8
#define BGP_NOTIFY_CEASE_MAX                     9

/* BGP_NOTIFY_CAPABILITY_ERR sub codes (draft-ietf-idr-dynamic-cap-02). */
#define BGP_NOTIFY_CAPABILITY_INVALID_ACTION     1
#define BGP_NOTIFY_CAPABILITY_INVALID_LENGTH     2
#define BGP_NOTIFY_CAPABILITY_MALFORMED_CODE     3
#define BGP_NOTIFY_CAPABILITY_MAX                4

/* BGP finite state machine status.  */
#define Idle                                     1
#define Connect                                  2
#define Active                                   3
#define OpenSent                                 4
#define OpenConfirm                              5
#define Established                              6
#define Clearing                                 7
#define Deleted                                  8
#define BGP_STATUS_MAX                           9

/* BGP finite state machine events.  */
#define BGP_Start                                1
#define BGP_Stop                                 2
#define TCP_connection_open                      3
#define TCP_connection_closed                    4
#define TCP_connection_open_failed               5
#define TCP_fatal_error                          6
#define ConnectRetry_timer_expired               7
#define Hold_Timer_expired                       8
#define KeepAlive_timer_expired                  9
#define Receive_OPEN_message                    10
#define Receive_KEEPALIVE_message               11
#define Receive_UPDATE_message                  12
#define Receive_NOTIFICATION_message            13
#define Clearing_Completed                      14
#define BGP_EVENTS_MAX                          15

/* BGP timers default value.  */
#define BGP_INIT_START_TIMER                     5
#define BGP_ERROR_START_TIMER                   30
#define BGP_DEFAULT_HOLDTIME                   180
#define BGP_DEFAULT_KEEPALIVE                   60
#define BGP_DEFAULT_ASORIGINATE                 15
#define BGP_DEFAULT_EBGP_ROUTEADV               30
#define BGP_DEFAULT_IBGP_ROUTEADV                5
#define BGP_CLEAR_CONNECT_RETRY                 20
#define BGP_DEFAULT_CONNECT_RETRY              120

/* BGP default local preference.  */
#define BGP_DEFAULT_LOCAL_PREF                 100

/* BGP graceful restart  */
#define BGP_DEFAULT_RESTART_TIME               120
#define BGP_DEFAULT_STALEPATH_TIME             360

/* RFC4364 */
#define SAFI_MPLS_LABELED_VPN                  128

/* Max TTL value.  */
#define TTL_MAX                                255

/* BGP uptime string length.  */
#define BGP_UPTIME_LEN 25

/* Default configuration settings for bgpd.  */
#define BGP_VTY_PORT                          2605
#define BGP_DEFAULT_CONFIG             "bgpd.conf"

/* Check AS path loop when we send NLRI.  */
/* #define BGP_SEND_ASPATH_CHECK */

/* Flag for peer_clear_soft().  */
enum bgp_clear_type
{
  BGP_CLEAR_SOFT_NONE,
  BGP_CLEAR_SOFT_OUT,
  BGP_CLEAR_SOFT_IN,
  BGP_CLEAR_SOFT_BOTH,
  BGP_CLEAR_SOFT_IN_ORF_PREFIX,
  BGP_CLEAR_SOFT_RSCLIENT
};

/* Macros. */
#define BGP_INPUT(P)         ((P)->ibuf)
#define BGP_INPUT_PNT(P)     (STREAM_PNT(BGP_INPUT(P)))

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* BGP error codes.  */
#define BGP_SUCCESS                               0
#define BGP_ERR_INVALID_VALUE                    -1
#define BGP_ERR_INVALID_FLAG                     -2
#define BGP_ERR_INVALID_AS                       -3
#define BGP_ERR_INVALID_BGP                      -4
#define BGP_ERR_PEER_GROUP_MEMBER                -5
#define BGP_ERR_MULTIPLE_INSTANCE_USED           -6
#define BGP_ERR_PEER_GROUP_MEMBER_EXISTS         -7
#define BGP_ERR_PEER_BELONGS_TO_GROUP            -8
#define BGP_ERR_PEER_GROUP_AF_UNCONFIGURED       -9
#define BGP_ERR_PEER_GROUP_NO_REMOTE_AS         -10
#define BGP_ERR_PEER_GROUP_CANT_CHANGE          -11
#define BGP_ERR_PEER_GROUP_MISMATCH             -12
#define BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT  -13
#define BGP_ERR_MULTIPLE_INSTANCE_NOT_SET       -14
#define BGP_ERR_AS_MISMATCH                     -15
#define BGP_ERR_PEER_INACTIVE                   -16
#define BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER   -17
#define BGP_ERR_PEER_GROUP_HAS_THE_FLAG         -18
#define BGP_ERR_PEER_FLAG_CONFLICT              -19
#define BGP_ERR_PEER_GROUP_SHUTDOWN             -20
#define BGP_ERR_PEER_FILTER_CONFLICT            -21
#define BGP_ERR_NOT_INTERNAL_PEER               -22
#define BGP_ERR_REMOVE_PRIVATE_AS               -23
#define BGP_ERR_AF_UNCONFIGURED                 -24
#define BGP_ERR_SOFT_RECONFIG_UNCONFIGURED      -25
#define BGP_ERR_INSTANCE_MISMATCH               -26
#define BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP  -27
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS    -28
#define BGP_ERR_TCPSIG_FAILED			-29
#define BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK	-30
#define BGP_ERR_NO_IBGP_WITH_TTLHACK		-31
#define BGP_ERR_MAX				-32
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS_REMOTE_AS    -33

extern struct bgp_master *bm;

extern struct thread_master *master;

/* Prototypes. */
extern void bgp_terminate (void);
extern void bgp_reset (void);
extern time_t bgp_clock (void);
extern void bgp_zclient_reset (void);
extern int bgp_nexthop_set (union sockunion *, union sockunion *,
		     struct bgp_nexthop *, struct peer *);
extern struct bgp *bgp_get_default (void);
extern struct bgp *bgp_lookup (as_t, const char *);
extern struct bgp *bgp_lookup_by_name (const char *);
extern struct peer *peer_lookup (struct bgp *, union sockunion *);
extern struct peer_group *peer_group_lookup (struct bgp *, const char *);
extern struct peer_group *peer_group_get (struct bgp *, const char *);
extern struct peer *peer_lookup_with_open (union sockunion *, as_t, struct in_addr *,
				    int *);
extern struct peer *peer_lock (struct peer *);
extern struct peer *peer_unlock (struct peer *);
extern bgp_peer_sort_t peer_sort (struct peer *peer);
extern int peer_active (struct peer *);
extern int peer_active_nego (struct peer *);
extern struct peer *peer_create_accept (struct bgp *);
extern char *peer_uptime (time_t, char *, size_t);
extern int bgp_config_write (struct vty *);
extern void bgp_config_write_family_header (struct vty *, afi_t, safi_t, int *);

extern void bgp_master_init (void);

extern void bgp_init (void);
extern void bgp_route_map_init (void);

extern int bgp_option_set (int);
extern int bgp_option_unset (int);
extern int bgp_option_check (int);

extern int bgp_get (struct bgp **, as_t *, const char *);
extern int bgp_delete (struct bgp *);

extern int bgp_flag_set (struct bgp *, int);
extern int bgp_flag_unset (struct bgp *, int);
extern int bgp_flag_check (struct bgp *, int);

extern void bgp_lock (struct bgp *);
extern void bgp_unlock (struct bgp *);

extern int bgp_router_id_set (struct bgp *, struct in_addr *);

extern int bgp_cluster_id_set (struct bgp *, struct in_addr *);
extern int bgp_cluster_id_unset (struct bgp *);

extern int bgp_confederation_id_set (struct bgp *, as_t);
extern int bgp_confederation_id_unset (struct bgp *);
extern int bgp_confederation_peers_check (struct bgp *, as_t);

extern int bgp_confederation_peers_add (struct bgp *, as_t);
extern int bgp_confederation_peers_remove (struct bgp *, as_t);

extern int bgp_timers_set (struct bgp *, u_int32_t, u_int32_t);
extern int bgp_timers_unset (struct bgp *);

extern int bgp_default_local_preference_set (struct bgp *, u_int32_t);
extern int bgp_default_local_preference_unset (struct bgp *);

#ifdef USE_SRX
extern int bgp_srx_set (struct bgp *, struct vty *, const char *, int, bool);
extern int bgp_srx_unset (struct bgp *bgp);

extern int bgp_srx_set_evaluation (struct bgp *, int);
extern int bgp_srx_unset_evaluation(struct bgp *, int);

// does both, set and unset
extern int bgp_srx_display (struct bgp *bgp, int);
extern int bgp_srx_conf_default_result (struct bgp *bgp, int, int);

// does set
extern int srx_set_proxyID(struct bgp* , uint32_t);

extern int srx_val_local_preference_set (struct bgp *bgp, int, int, bool, uint32_t);
extern int srx_val_local_preference_unset (struct bgp *, int, int);
extern int srx_val_policy_set (struct bgp *, uint16_t);
extern int srx_val_policy_unset (struct bgp *, uint16_t);

extern int srx_extcommunity_set (struct bgp *, uint8_t, const char *);
extern int srx_extcommunity_unset (struct bgp *);

extern int srx_config_check (struct bgp *, uint16_t);

extern int srx_connect_proxy(struct bgp *);
#define DEBUG_TEST
#endif /* USE_SRX */

extern int peer_rsclient_active (struct peer *);

extern int peer_remote_as (struct bgp *, union sockunion *, as_t *, afi_t, safi_t);
extern int peer_group_remote_as (struct bgp *, const char *, as_t *);
extern int peer_delete (struct peer *peer);
extern int peer_group_delete (struct peer_group *);
extern int peer_group_remote_as_delete (struct peer_group *);

extern int peer_activate (struct peer *, afi_t, safi_t);
extern int peer_deactivate (struct peer *, afi_t, safi_t);

extern int peer_group_bind (struct bgp *, union sockunion *, struct peer_group *,
		     afi_t, safi_t, as_t *);
extern int peer_group_unbind (struct bgp *, struct peer *, struct peer_group *,
		       afi_t, safi_t);

extern int peer_flag_set (struct peer *, u_int32_t);
extern int peer_flag_unset (struct peer *, u_int32_t);

extern int peer_af_flag_set (struct peer *, afi_t, safi_t, u_int32_t);
extern int peer_af_flag_unset (struct peer *, afi_t, safi_t, u_int32_t);
extern int peer_af_flag_check (struct peer *, afi_t, safi_t, u_int32_t);

extern int peer_ebgp_multihop_set (struct peer *, int);
extern int peer_ebgp_multihop_unset (struct peer *);

extern int peer_description_set (struct peer *, char *);
extern int peer_description_unset (struct peer *);

extern int peer_update_source_if_set (struct peer *, const char *);
extern int peer_update_source_addr_set (struct peer *, union sockunion *);
extern int peer_update_source_unset (struct peer *);

extern int peer_default_originate_set (struct peer *, afi_t, safi_t, const char *);
extern int peer_default_originate_unset (struct peer *, afi_t, safi_t);

extern int peer_port_set (struct peer *, u_int16_t);
extern int peer_port_unset (struct peer *);

extern int peer_weight_set (struct peer *, u_int16_t);
extern int peer_weight_unset (struct peer *);

extern int peer_timers_set (struct peer *, u_int32_t, u_int32_t);
extern int peer_timers_unset (struct peer *);

extern int peer_timers_connect_set (struct peer *, u_int32_t);
extern int peer_timers_connect_unset (struct peer *);

extern int peer_advertise_interval_set (struct peer *, u_int32_t);
extern int peer_advertise_interval_unset (struct peer *);

extern int peer_interface_set (struct peer *, const char *);
extern int peer_interface_unset (struct peer *);

extern int peer_distribute_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_distribute_unset (struct peer *, afi_t, safi_t, int);

extern int peer_allowas_in_set (struct peer *, afi_t, safi_t, int);
extern int peer_allowas_in_unset (struct peer *, afi_t, safi_t);

extern int peer_local_as_set (struct peer *, as_t, int, int);
extern int peer_local_as_unset (struct peer *);

extern int peer_prefix_list_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_prefix_list_unset (struct peer *, afi_t, safi_t, int);

extern int peer_aslist_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_aslist_unset (struct peer *,afi_t, safi_t, int);

extern int peer_route_map_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_route_map_unset (struct peer *, afi_t, safi_t, int);

extern int peer_unsuppress_map_set (struct peer *, afi_t, safi_t, const char *);

extern int peer_password_set (struct peer *, const char *);
extern int peer_password_unset (struct peer *);

extern int peer_unsuppress_map_unset (struct peer *, afi_t, safi_t);

extern int peer_maximum_prefix_set (struct peer *, afi_t, safi_t, u_int32_t, u_char, int, u_int16_t);
extern int peer_maximum_prefix_unset (struct peer *, afi_t, safi_t);

extern int peer_clear (struct peer *);
extern int peer_clear_soft (struct peer *, afi_t, safi_t, enum bgp_clear_type);

extern int peer_ttl_security_hops_set (struct peer *, int);
extern int peer_ttl_security_hops_unset (struct peer *);

#endif /* _QUAGGA_BGPD_H */
