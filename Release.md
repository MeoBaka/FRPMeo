## Features

* The frps dashboard can now be covered by the firewall, behind a switch of its own next to the control-port switch. It is off by default: the dashboard is where firewall rules are written, so a rule that closes its port can only be undone by editing `frps_firewall.json` on the host and restarting. The check runs when the connection is accepted, before the TLS handshake, so a refused peer never reaches it.
* The frps ssh tunnel gateway is now covered by the firewall. It opens a port of its own that none of the existing checks reached, so a client turned away at the control port had a second way in. It answers to the control-port switch, since both are how a client reaches frps.
* A reputation provider can return the reason it blocked an address, read from a configurable JSON path and shown in the rejection log. In `frpcontrol` mode the path defaults to `results.0.reason`, so nothing needs configuring; a provider that does not answer with one is unaffected.

## Improvements

* Firewall rules are parsed when they are added rather than on every connection. Deciding one connection against ten rules went from 1907 ns and 42 allocations to 127 ns and none, and the decision no longer allocates at all. The decisions themselves are unchanged.
* Firewall rejection log lines are shorter and no longer repeat the proxy name that the logger already prints.
* The frps dashboard no longer writes TLS handshake failures to stderr with the standard logger, where the configured log level, the log file and its rotation could not reach them. They now go to the frp logger at debug level, which keeps scanner noise out of a default log.

## Fixes

* A firewall rule saved without an id reported `rule ` in the log, naming nothing. It now reports its position in the rule list.
* A firewall rule written by hand with whitespace around its action, such as `" allow "`, was read as a deny. The action is now trimmed before it is read.
