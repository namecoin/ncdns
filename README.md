ncdns
=====

A Go daemon to bridge Namecoin to DNS. The daemon acts as an authoritative
nameserver and queries a Namecoin daemon over JSON-RPC in order to obtain zone
data.

The daemon can optionally sign zones with DNSSEC and supports the use of DS
records in Namecoin. It works best when used by Unbound or another recursive
resolver, or as an authoritative nameserver for a stub zone.

Using ncdns to provide a suffix
-------------------------------
The daemon acts as an authoritative nameserver for any name containing a 'bit'
label. For example, all of the following queries return the same records:

  - example.bit.
  - example.bit.example.com.

This enables the easy use of suffixes. (Note that this will cause a different
hostname to be transmitted for protocols like HTTP, and server configuration
may need to be modified to enable this. In some cases there may be no simple
solution to enabling arbitrary suffix use with a given piece of server
software, in which known suffixes can be configured; patches for such software
would be desirable.)

Using ncdns with a recursive resolver
-------------------------------------
Of course the daemon can also be used simply as an authoritative nameserver for
bit. directly. One way to do this is to run a recursive resolver (such as
Unbound) and configure it to serve the zone as a 'stub zone'. Here is an example
unbound configuration:

    server:
      do-not-query-localhost: no
    stub-zone:
      name: bit.
      stub-addr: 127.0.0.1@1153

If you don't want to use DNSSEC, also add:

    server:
      domain-insecure: bit.

If you do want to use DNSSEC, see the instructions below.

Note how you can specify a port other than 53. This allows you to run both
Unbound and ncdns on the same machine. Alternately, you could add an additional
loopback IP address (127.0.0.2) and bind ncdns to that. This is useful if your
recursive resolver doesn't support a port number other than 53.

Using DNSSEC
------------
To use DNSSEC, generate keys with `dnssec-keygen` or `ldns-keygen`. You will need
to generate a key-signing key and a zone-signing key:

    # Generate KSK.
    $ dnssec-keygen -a RSASHA256 -3 -b 2048 -f KSK bit

    # Generate ZSK.
    $ dnssec-keygen -a RSASHA256 -3 -b 2048 bit

Each of these commands will generate a pair of files, a `.key` file and a
`.private` file.  Make a note of which is the KSK and which is the ZSK. If you
forget, check the comments inside the .key file. (If there are no comments for
some reason, a KSK usually contains the string `DNSKEY 256` and a ZSK
`DNSKEY 257`.)

(You could substitute something else for `bit` as ncdns doesn't care. However
if you want to use the key as a trust anchor with a recursive resolver such as
unbound, you should specify `bit`.)

If using Unbound as a recursive resolver, you should add the KSK's public key file
as a trust anchor to unbound like so:

    server:
      trust-anchor-file: "/etc/unbound/keys/bit.key"

`bit.key` should be the file containing the KSK DNSKEY (or DS) which ncdns is
configured to use.

Building
--------

Prerequisites:

1. Ensure you have the Go tools installed.

2. If using Linux, ensure you have the `libcap` development headers
   installed. (Most distributions will have a package called `libcap-dev` or
   similar.)

Option A: Using Go build commands (works on any platform with Bash):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `go get -d -t -u github.com/namecoin/ncdns/...`. The ncdns source code will be
   retrieved automatically.

3. Run `go generate github.com/namecoin/ncdns/...`.  Some source code will be generated.

4. Run `go get -t github.com/namecoin/ncdns/...`.  ncdns will be built. The binaries will be at
   $GOPATH/bin/ncdns.

Option B: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

ncdns can be run as a Windows service; see the output of `ncdns --help`.

Configuration
-------------
ncdns uses a configuration file which is looked for at `../etc/ncdns.conf`
(relative to the executable path) and `/etc/ncdns/ncdns.conf`. You can override
this and all options on the command line. An annotated example configuration
file `ncdns.conf.example` is available in doc.

You will need to setup a `namecoind`, `namecoin-qt` or compatible Namecoin node
and enable the JSON-RPC interface. You will then need to provide `ncdns` with
the address of this interface and any necessary username and password via the
configuration file.

If you only want to resolve .bit names yourself, here is a suggested setup on
Linux:

  - Install `namecoind` (or `namecoin-qt`) and set it to start automatically
    at boot or login. Set up the JSON-RPC interface and make sure it works
    by making a test query: `namecoind name_show d/example`.

  - Write a ncdns configuration file and set ncdns up to start at boot.
    Since Unbound will tie up port 53, set a different port (ideally one >=1024,
    so it needn't be run as root.) Test that ncdns works by trying to resolve
    a `.bit` domain. If you want to use DNSSEC, generate keys as shown above
    and configure ncdns appropriately.

  - Install and setup the Unbound recursive resolver on your system. On most
    systems, the recommended way to install Unbound is to install DNSSEC
    Trigger, which installs and configures Unbound automatically.

    If you wish to use DNSSEC, add the ncdns DNSKEY to Unbound as a trust
    anchor as shown above. See above for configuration suggestions.

  - Edit `/etc/resolv.conf` to point to the Unbound resolver at 127.0.0.1.
    (If this file is generated automatically via DHCP or similar, you may
     find these changes keep getting wiped out. Either reconfigure whatever
     keeps overwriting it to stop doing so, or, as a stopgap measure, make
     the file immutable using `chattr +i`.)

Licence
-------
    Licenced under the GPLv3 or later.
    © 2014-2015 Hugo Landau <hlandau@devever.net>
