# ===========================================================================
#  kmitl-authen for MikroTik RouterOS v7  (native RouterOS script, no Python)
# ===========================================================================
#
#  RouterOS cannot run Python. This is a port of the same logic to RouterOS
#  script, driven by /system scheduler instead of a loop:
#
#      probe -> if offline, login -> else heartbeat
#
#  WHAT YOU GET
#      * survives reboots (scheduler + startup script)
#      * logging through RouterOS /log, so /log print follows it
#      * force re-login:  /system script run kmitl-force-relogin
#      * status:          /system script environment print where name~"kmitl"
#
#  LIMITATIONS, read these before relying on it
#      1. /tool fetch keeps NO COOKIE JAR. The login and heartbeat calls here
#         pass everything as query parameters, which is how the portal's own
#         API works, so this normally succeeds -- but if KMITL ever moves to a
#         session cookie, this script stops working and the container route
#         below is the only option. Verify once with `/log print` after install.
#      2. There is no URL-encoder in RouterOS script. If your password contains
#         any of  & ? # % + space  you must percent-encode it by hand in
#         kmitlPass below (e.g. "p@ss word" -> "p%40ss%20word").
#      3. No TLS trust store by default, hence check-certificate=no. Import the
#         CA with /certificate import if you want real verification.
#      4. The router authenticates ITSELF, with its own IP and MAC. Clients
#         behind it reach the internet through its NAT.
#
#  INSTALL
#      1. Edit the five :global lines below.
#      2. Upload this file to the router (Files, or scp), then:
#             /import file-name=kmitl-authen.rsc
#      3. Check it:
#             /log print where message~"kmitl"
#
#  UNINSTALL
#      /system scheduler remove [find name~"kmitl"]
#      /system script remove [find name~"kmitl"]
#
# ===========================================================================

# --------------------------------------------------------------------------
#  1. Settings  --  EDIT THESE
# --------------------------------------------------------------------------
/system script
add name=kmitl-config dontrequirepermissions=no policy=read,write,test,policy comment="kmitl-authen: settings" source={
    :global kmitlUser        "65010000";
    :global kmitlPass        "your-password";
    # Leave kmitlAddr "" to use the address of kmitlIface below.
    :global kmitlAddr        "";
    :global kmitlIface       "ether1";
    :global kmitlAcip        "10.252.13.10";

    :global kmitlLoginUrl    "https://portal.kmitl.ac.th:19008/portalauth/login";
    :global kmitlLogoutUrl   "https://portal.kmitl.ac.th:19008/portalauth/logout";
    :global kmitlBeatUrl     "https://nani.csc.kmitl.ac.th/network-api/data/";
    :global kmitlProbeUrl    "http://detectportal.firefox.com/success.txt";

    # Proactive re-login after this many heartbeat ticks (96 x 5min = 8h).
    :global kmitlReloginTicks 96;
}

# --------------------------------------------------------------------------
#  2. Helpers
# --------------------------------------------------------------------------
/system script
add name=kmitl-lib dontrequirepermissions=no policy=read,write,test,policy,reboot comment="kmitl-authen: helper functions" source={
    :global kmitlUser;  :global kmitlPass;  :global kmitlAddr;
    :global kmitlIface; :global kmitlAcip;
    :global kmitlLoginUrl; :global kmitlLogoutUrl;
    :global kmitlBeatUrl;  :global kmitlProbeUrl;

    # --- state, readable with: /system script environment print ---
    :global kmitlState;        # online | offline | logging-in | blocked
    :global kmitlLastLogin;
    :global kmitlLastBeat;
    :global kmitlTicks;
    :global kmitlFails;
    :global kmitlForce;
    :if ([:typeof $kmitlTicks] = "nothing") do={ :set kmitlTicks 0 }
    :if ([:typeof $kmitlFails] = "nothing") do={ :set kmitlFails 0 }
    :if ([:typeof $kmitlForce] = "nothing") do={ :set kmitlForce false }
    :if ([:typeof $kmitlState] = "nothing") do={ :set kmitlState "offline" }

    # --- our own address on the campus-facing interface ---
    :global kmitlGetAddr do={
        :global kmitlAddr; :global kmitlIface;
        :if ([:len $kmitlAddr] > 0) do={ :return $kmitlAddr }
        # A DHCP lease first, then a static address.
        :local dhcp [/ip dhcp-client find interface=$kmitlIface];
        :if ([:len $dhcp] > 0) do={
            :local got [/ip dhcp-client get [:pick $dhcp 0] address];
            :if ([:len $got] > 0) do={ :return [:pick $got 0 [:find $got "/"]] }
        }
        :local static [/ip address find interface=$kmitlIface disabled=no];
        :if ([:len $static] > 0) do={
            :local got [/ip address get [:pick $static 0] address];
            :return [:pick $got 0 [:find $got "/"]]
        }
        :return "";
    }

    # --- MAC of the campus-facing interface, as 12 bare hex digits ---
    :global kmitlGetMac do={
        :global kmitlIface;
        :local found [/interface find name=$kmitlIface];
        :if ([:len $found] = 0) do={ :return "" }
        :local raw [/interface get [:pick $found 0] mac-address];
        # RouterOS reports "E4:8D:8C:11:22:33"; the portal expects
        # "e48d8c112233". RouterOS script has no :tolower, so map by hand.
        :local upper "ABCDEF";
        :local lower "abcdef";
        :local out "";
        :for i from=0 to=([:len $raw] - 1) do={
            :local ch [:pick $raw $i];
            :if ($ch != ":" && $ch != "-") do={
                :local at [:find $upper $ch];
                :if ([:typeof $at] != "nil") do={
                    :set out ($out . [:pick $lower $at]);
                } else={
                    :set out ($out . $ch);
                }
            }
        }
        :return $out;
    }

    # --- true when the internet is reachable without the portal ---
    :global kmitlProbe do={
        :global kmitlProbeUrl;
        :do {
            :local r [/tool fetch url=$kmitlProbeUrl mode=http output=user \
                        as-value http-method=get];
            :local body ($r->"data");
            :if ([:typeof [:find $body "success"]] != "nil") do={ :return true }
            :return false;
        } on-error={ :return false }
    }

    # --- POST the login form; returns true when the portal accepted it ---
    :global kmitlLogin do={
        :global kmitlUser; :global kmitlPass; :global kmitlAcip;
        :global kmitlLoginUrl; :global kmitlGetAddr; :global kmitlGetMac;
        :global kmitlState; :global kmitlLastLogin; :global kmitlFails;

        :local addr [$kmitlGetAddr];
        :local mac  [$kmitlGetMac];
        :if ([:len $addr] = 0 || [:len $mac] = 0) do={
            :log error "kmitl-authen: cannot determine address/MAC (check kmitlIface)";
            :return false;
        }

        :set kmitlState "logging-in";
        :local url ($kmitlLoginUrl . "?userName=" . $kmitlUser . \
                    "&userPass=" . $kmitlPass . "&uaddress=" . $addr . \
                    "&umac=" . $mac . "&agreed=1&acip=" . $kmitlAcip . "&authType=1");
        :do {
            :local r [/tool fetch url=$url http-method=post output=user as-value \
                        check-certificate=no \
                        http-header-field="X-Requested-With: XMLHttpRequest,Referer: https://portal.kmitl.ac.th:19008/"];
            :local body ($r->"data");

            # Credential rejection is permanent: stop, do not keep hammering,
            # or the account gets locked.
            :if ([:typeof [:find $body "userPassError"]] != "nil") do={
                :set kmitlFails ($kmitlFails + 1);
                :set kmitlState "blocked";
                :log error ("kmitl-authen: portal rejected the credentials (" . \
                            $kmitlFails . " times) -- fix kmitl-config");
                :return false;
            }
            :if ([:typeof [:find $body "\"success\":true"]] != "nil" || \
                 [:typeof [:find $body "already"]] != "nil") do={
                :set kmitlLastLogin [/system clock get time];
                :set kmitlFails 0;
                :set kmitlState "online";
                :log info ("kmitl-authen: login ok as " . $kmitlUser . \
                           " addr=" . $addr . " mac=" . $mac);
                :return true;
            }
            :set kmitlFails ($kmitlFails + 1);
            :log warning ("kmitl-authen: login rejected: " . [:pick $body 0 160]);
            :return false;
        } on-error={
            :set kmitlFails ($kmitlFails + 1);
            :log warning "kmitl-authen: login request failed (network or TLS error)";
            :return false;
        }
    }

    # --- keep the portal session alive ---
    :global kmitlBeat do={
        :global kmitlUser; :global kmitlBeatUrl; :global kmitlLastBeat;
        :local url ($kmitlBeatUrl . "?username=" . $kmitlUser . \
                    "&os=RouterOS&speed=1.29&newauth=1");
        :do {
            /tool fetch url=$url http-method=post output=none check-certificate=no;
            :set kmitlLastBeat [/system clock get time];
            :return true;
        } on-error={
            :log warning "kmitl-authen: heartbeat failed";
            :return false;
        }
    }

    :global kmitlLogout do={
        :global kmitlLogoutUrl; :global kmitlState;
        :do {
            /tool fetch url=$kmitlLogoutUrl http-method=post output=none \
                check-certificate=no;
            :set kmitlState "offline";
            :log info "kmitl-authen: logged out";
        } on-error={ :log warning "kmitl-authen: logout failed" }
    }
}

# --------------------------------------------------------------------------
#  3. The tick the scheduler runs
# --------------------------------------------------------------------------
/system script
add name=kmitl-tick dontrequirepermissions=no policy=read,write,test,policy,reboot comment="kmitl-authen: scheduled tick" source={
    /system script run kmitl-config;
    /system script run kmitl-lib;

    :global kmitlProbe; :global kmitlLogin; :global kmitlBeat;
    :global kmitlState; :global kmitlTicks; :global kmitlFails;
    :global kmitlForce; :global kmitlReloginTicks;

    # Give up after repeated credential rejections, exactly like the Python
    # version's max_credential_failures. Clear kmitlFails to resume.
    :if ($kmitlState = "blocked" && $kmitlFails >= 3 && !$kmitlForce) do={
        :log warning "kmitl-authen: blocked on bad credentials; fix kmitl-config, then :global kmitlFails 0";
        :error "blocked";
    }

    :if ($kmitlForce) do={
        :set kmitlForce false;
        :log info "kmitl-authen: forced re-login";
        $kmitlLogin;
        :set kmitlTicks 0;
    } else={
        :if ([$kmitlProbe]) do={
            :set kmitlState "online";
            :set kmitlTicks ($kmitlTicks + 1);
            :if ($kmitlTicks >= $kmitlReloginTicks) do={
                :log info "kmitl-authen: scheduled re-login";
                $kmitlLogin;
                :set kmitlTicks 0;
            } else={
                :if (![$kmitlBeat]) do={
                    # The portal stopped recognising us: log in again now
                    # instead of waiting out another interval.
                    $kmitlLogin;
                }
            }
        } else={
            :set kmitlState "offline";
            :log info "kmitl-authen: offline, logging in";
            $kmitlLogin;
            :set kmitlTicks 0;
        }
    }
}

# --------------------------------------------------------------------------
#  4. Force re-login  --  /system script run kmitl-force-relogin
# --------------------------------------------------------------------------
/system script
add name=kmitl-force-relogin dontrequirepermissions=no policy=read,write,test,policy,reboot comment="kmitl-authen: force a re-login now" source={
    :global kmitlForce true;
    :global kmitlFails 0;
    :log info "kmitl-authen: re-login requested";
    /system script run kmitl-tick;
}

# --------------------------------------------------------------------------
#  5. Schedulers
# --------------------------------------------------------------------------
/system scheduler
add name=kmitl-heartbeat interval=5m start-time=startup \
    comment="kmitl-authen: probe + heartbeat, with login on failure" \
    policy=read,write,test,policy,reboot \
    on-event="/system script run kmitl-tick"

# A short boot delay: the WAN interface needs its address before we can log in.
add name=kmitl-boot interval=0 start-time=startup \
    comment="kmitl-authen: first login after boot" \
    policy=read,write,test,policy,reboot \
    on-event=":delay 30s; /system script run kmitl-force-relogin"

:log info "kmitl-authen: installed. Edit kmitl-config, then: /system script run kmitl-force-relogin"
