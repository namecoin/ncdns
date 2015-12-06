
{{define "Main"}}<h1>Namecoin DNS Services</h1>
		<p><strong>Access any Namecoin .bit domain by appending "{{.TLD}}".</strong> For example, <em>example.bit</em> becomes <em>example.{{.CanonicalSuffix}}</em>. <a href="#caveats">Caveats.</a></p>

    

		<a name="lookup"></a>
		<form method="GET" action="/lookup" class="lookup-form">
			<fieldset>
				<legend>Check a domain name</legend>
				<input type="text" name="q" value="" placeholder="Enter domain name in form d/example or example.bit" size="67" required="required" maxlength="67" pattern="^(d/[a-z0-9_-]+|[a-z0-9_-]+\.bit\.?)$" x-moz-errormessage="Must be in the form d/example or example.bit." />
				<input type="submit" value="Lookup Domain" />
				<p>You can use this lookup tool to check the validity of a domain's configuration.</p>
				<p>Other tools: <a href="/lookup">Validate JSON</a></p>
			</fieldset>
		</form>

		<p>{{.CanonicalSuffix}} provides public Namecoin authoritative DNS services. The nameservers it provides can be used
		   to convert domain names into Namecoin suffixes, or directly to query the .bit zone.</p>
		<ol>
			<li><p>The {{.CanonicalSuffix}} nameservers are authoritative for the .bit zone. For example:</p>
				<pre>$ dig A nf.bit. @{{.SelfName}}
94.23.252.190</pre>
				<p>You can use the nameservers in this mode by configuring a suitable DNS resolver.
				   Unbound is recommended due to its support for {{if .HasDNSSEC}} DNSSEC and {{end}} configurable
					 stub zones. <a href="#unbound">See how to configure Unbound.</a></p>
			</li>

			<li><p>The {{.CanonicalSuffix}} nameservers are authoritative for any matching suffix. A suffix matches
			if it contains the label "bit". Such suffixes are automatically aliased to the "bit" zone.
			For example, "example.{{.CanonicalSuffix}}" is equivalent to "example.bit", but because it uses an ICANN TLD,
			it can be accessed without prior configuration.</p>

			<p>Since the {{.CanonicalSuffix}} nameservers automatically recognise any suffix containing the label "bit", you
			can convert any suitable name (of the form bit.<em>tld</em>, or rather more verbosely bit.<em>yourdomain.tld</em>) to a .bit suffix by changing its nameservers to those of {{.CanonicalSuffix}}.</p>

			<p>There are a number of caveats to this mode of operation; see <a href="#caveats">Caveats</a>.</p>
			</li>
		</ol>

		<p>Both of these modes of operation require you to trust the <em>{{.CanonicalSuffix}}</em> operator (and the operator of {{.TLD}}, and ICANN, etc.); see <a href="#caveats">Caveats</a>.</p>

		<a name="ns"></a>
		<h2>Nameservers</h2>
		<p>The following nameservers are provided for public use in the modes described above:</p>
		<ol>
		{{range .CanonicalNameservers}}
			<li>{{.}}</li>
		{{end}}
		</ol>
		
		<a name="unbound"></a>
		<h2>Configuring Unbound</h2>
		<p>The following is an example of the directives which should be placed in an Unbound configuration file:</p>
		<pre>server:
  # (other directives omitted){{if .HasDNSSEC}}
  trust-anchor-file: "/etc/unbound/keys/{{.CanonicalSuffix}}.key"{{end}}
  stub-zone:
    name: bit.
{{range .CanonicalNameservers}}    stub-host: {{.}}
{{end}}    stub-prime: yes</pre>
		{{if .HasDNSSEC}}<p>You will need to place the {{.CanonicalSuffix}} trust anchor (a DS record) in <code>/etc/unbound/keys/{{.CanonicalSuffix}}.key</code>. See <a href="#dnssec">DNSSEC</a>.</p>{{end}}
		<p>See the <a href="http://www.unbound.net/">Unbound</a> documentation for information on setting up Unbound.</p>

		<a name="caveats"></a>
		<h2>Caveats</h2>
		<p>Using a suffix has the following caveats:</p>
		<ul>
			<h3>Operational Caveats</h3>
			<li>Due to the use of virtual hosting, some websites may not work correctly with a suffix as they may
			not recognise the hostname as that of the desired website. This can be rectified by the website operator via appropriate configuration, as most common webservers support the specification of virtual hostnames using regexes. See <a href="#www-config">Webserver Configuration</a>.</li>
			<li>Namecoin domains which delegate to nameservers are highly unlikely to work with a suffix, unless such nameservers have been specially modified to recognise .bit suffixes. For most nameserver software, this would require a patch, and this in itself is not feasible for those using hosted DNS services. However, domains which delegate to nameservers are currently rare. No patches are yet available.</li>

			<h3>Trust Caveats</h3>
			<li><p>Since the {{.CanonicalSuffix}} service is a central service, it is subject to attack, control and usurpation. Use of the {{.CanonicalSuffix}} service does not and cannot offer you the same level of trust and certainty of name data that is provided by using your own Namecoin node and DNS resolution daemon. As such, <strong>the {{.CanonicalSuffix}} service is suitable for low-security applications only</strong> (whether used in .bit or suffix mode).</p>
			
			<p>Since {{.CanonicalSuffix}} supports <a href="#dnssec">DNSSEC</a>, you can however at the very least protect yourself from MitM attacks against {{.CanonicalSuffix}}. This requires you to use a validating resolver such as <a href="http://www.unbound.net/">Unbound</a> (<a href="#unbound">configuration example</a>).</p> If you do this, then the risks inherent in the use of the {{.CanonicalSuffix}} are limited to the following threats:</p>
				<ol>
					<h4>False Name Attacks</h4>
					<li>The operator of {{.CanonicalSuffix}} starts acting maliciously or otherwise begins serving false name information.</li>
					<li>The operator of the {{.TLD}} TLD usurps control of the {{.CanonicalSuffix}} domain and changes the nameservers and DNSSEC keys registered for the domain. They then start executing attack no. 1.</li>
					<li>The operator of the root zone (IANA/ICANN), a court, a law enforcement authority or a government applies pressure or successfully coerces or legally or contractually obliges the operator of the {{.TLD}} TLD to execute attack no. 2.</li>
					<li>The {{.CanonicalSuffix}} nameservers become compromised and this access is used to make them serve false name data.</li>
					<li>The organizations proviing hosting for the {{.CanonicalSuffix}} nameservers decide to execute attack 5.</li>

					<h4>Denial of Service Attacks</h4>
					<li>The operator of {{.CanonicalSuffix}} ceases operating, thus preventing use of the {{.CanonicalSuffix}} suffix or the {{.CanonicalSuffix}} nameservers.</li>
					<li>The operator of the {{.TLD}} TLD suspends the {{.CanonicalSuffix}} domain, thus preventing use of the {{.CanonicalSuffix}} suffix.</li>
					<li>The operator of the root zone (IANA/ICANN), a court, a law enforcement authority or a government applies pressure or successfully coerces or legally or contractually obliges the operator of the {{.TLD}} TLD to execute attack no. 6.</li>
					<li>The {{.CanonicalSuffix}} service is placed under a resource consumption denial of service attack (i.e. bandwidth consumption or CPU consumption).</li>
					<li>An ISP or other network provider is compelled to blackhole or otherwise intercept traffic to the {{.CanonicalSuffix}} nameservers.</li>
					<li>All organizations providing hosting for all {{.CanonicalSuffix}} nameservers decide to terminate service to those nameservers, possibly due to compulsion by another entity.</li>

					<h4>Privacy Attacks</h4>
					<li>The operator of {{.CanonicalSuffix}} begins logging requests made<!---->.</li>
					<li>An ISP or other network provider begins logging requests made to the {{.CanonicalSuffix}} nameservers.</li>
					<li>The {{.CanonicalSuffix}} nameservers become compromised and they are reconfigured to begin logging requests made; these logs are then transferred to the attacker.</li>

					<h4>Stale Data Attacks</h4>
					<li>The Namecoin nodes used to provide data to the {{.CanonicalSuffix}} nameservers are Sybilled or otherwise prevented from communicating with the Namecoin network. Thus new name data is no longer seen, and old name data for all names is sustained perpetually.</li>

					<h4>Other</h4>
					<li>Of course, all attacks applicable to Namecoin itself also apply.</li>
				</ol>
			
				<p>The necessarily trusted parties in terms of False Name attacks are therefore the {{.CanonicalSuffix}} operators, the organizations providing hosting for the {{.CanonicalSuffix}} nameservers, the {{.TLD}} TLD registry (which doubles as the registrar) and ICANN/IANA, but also all courts, law enforcement agencies and/or governments of competent jurisdiction or practical authority.</p>
			</li>
		</ul>

		<a name="dnssec"></a>
		<h2>DNSSEC</h2>
    {{if .HasDNSSEC}}
		<p>The {{.CanonicalSuffix}} nameservers support DNSSEC. For use as a suffix, operation is automatic so long as you use a validating resolver. (Third party suffixes using the {{.CanonicalSuffix}} nameservers should avoid attempting to configure DS records at this time due to the potential need for KSK rollover.)</p>

		<p>If using the {{.CanonicalSuffix}} nameservers to access .bit directly, a DNSSEC trust anchor must be configured. You should use a validating resolver to lookup the DS records for {{.CanonicalSuffix}} and use those as the trust anchor. See <a href="#unbound">Unbound</a> for details on how to configure Unbound.</p>


    {{else}}
    <p>The {{.CanonicalSuffix}} nameservers do <strong>not</strong> support DNSSEC.</p>
    {{end}}

		<a name="www-config"></a>
		<h2>Webserver Configuration</h2>
		<h3>Apache</h3>
		<p>You can configure a virtual host in Apache which responds to any hostname of the form "example.bit.X." using the following:</p>
		<pre>&lt;VirtualHost ...&gt;
  ServerName example.bit
  ServerAlias example.bit.*
&lt;/VirtualHost&gt;</pre>

		<h3>Nginx</h3>
		<p>You can configure a virtual host in nginx which responds to any hostname of the form "example.bit.X." using the following:</p>
		<pre>server {
  listen 80;
  server_name example.bit example.bit.*;
}</pre>
		<p>nginx also supports regexes for server names; see the <a href="http://nginx.org/en/docs/http/server_names.html">nginx documentation</a>.</p>

		<h3>Lighttpd</h3>
		<p>Lighttpd can use regexes to match hostnames, so configuring suffix support is easy:</p>
		<pre>$HTTP["host"] =~ "(^|\.)example\.bit(\..*)?$" {
  ...
}</pre>

    <h2>Origin Issues</h2>

    <p>Web browsers use a database of <a href="http://publicsuffix.org/">public suffixes</a> to determine the maximum domain scope at which a cookie can be set. For example, a site a.b.c.com can set a cookie at a.b.c.com and c.com but not com. Conversely, domains such as this one can have cookies set on them by domains under them. example.{{.CanonicalSuffix}} can set a cookie for {{.CanonicalSuffix}}, thereby creating a “supercookie” which tracks users over all domains under the suffix.</p>
    

    <p>The optimal solution to this is to have the domain placed on the <a href="http://publicsuffix.org/">public suffix list</a>. However even when this is done it may take some time to be rolled out.</p>

    <p>This page will erase all cookies visible to it whenever you visit it. Thus visiting this page will always erase any suffix-wide supercookies. This is the least (and most) that can be done about the issue without the use of the public suffix list.</p>



<a name="source"></a>
<h2>Source Code</h2>
<p>Each {{.CanonicalSuffix}} nameserver runs a Namecoin full node  and <a href="https://github.com/hlandau/ncdns.t">ncdns</a>, a daemon for serving DNS records from the Namecoin .bit zone. ncdns relies on the full node.</p>
<p>This has the advantage that each nameserver is operationally completely independent of one another (aside from possessing the same zone signing private key, as described above).</p>
<p>This software is open source. </p>

<h2>Point of Contact</h2>
<p>Send enquiries, issues, questions, threats, etc. to <a href="mailto:{{.Hostmaster}}">{{.Hostmaster}}</a>.

{{end}}
