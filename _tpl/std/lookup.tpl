
{{define "Main"}}
		<form method="POST" action="/lookup" class="lookup-form">
			<fieldset>
				<legend>Check a domain name</legend>
				<input type="text" name="q" value="{{.Query}}" autofocus="autofocus" placeholder="Enter domain name in form d/example or example.bit" size="67" required="required" maxlength="67" pattern="^(d/[a-z0-9_-]+|[a-z0-9_-]+\.bit\.?)$" x-moz-errormessage="Must be in the form d/example or example.bit." />
				<input type="submit" value="Lookup Domain" />
				<p>To specify the JSON to validate rather than looking it up via Namecoin, specify it below. (You must still specify the name for the purposes of relative name lookup.)</p>
				<textarea name="value" class="jsonField" rows="10">{{.JSONValue}}</textarea>
			</fieldset>
		</form>
{{if .Query}}
		<pre>
{{if .NameParseError}}
Invalid name: {{.Query}}
{{else}}
Namecoin Name:  <span class="rv">{{.NamecoinName}}</span>
Domain Name:    <span class="rv">{{.DomainName}}</span>
Bare Name:      <span class="rv">{{.BareName}}</span>

Exists:         {{if .ExistenceError}}{{.ExistenceError}}{{else}}Yes{{end}}
{{if not .ExistenceError}}Expired:        {{.Expired}}{{end}}
{{if not .ExistenceError}}
Valid:          {{.Valid}}

Raw Value:
<span class="rv">{{.Value}}</span>
{{if .ParseErrors}}
Parse Errors:{{range .ParseErrors}}
  {{.}}{{end}}
{{end}}{{if .ParseWarnings}}
Parse Warnings:{{range .ParseWarnings}}
  {{.}}{{end}}
{{end}}
{{.NCValue}}
{{if .Advanced}}
Parsed Value:   {{.NCValueFmt | printf "%# v"}}
{{end}}
RRs:{{range .RRs}}
  <span class="rv">{{.}}</span>{{end}}

{{if .RRError}}
RR Generation Error: {{.RRError}}
{{end}}

{{end}}
{{end}}
</pre>
{{end}}
{{end}}
