
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
  <!-- This is the information page for {{.CanonicalSuffix}}. You should not use it unless you
       are running a service endorsed by {{.CanonicalSuffix}}. If you want to run your own service,
       you should change all references to {{.CanonicalSuffix}}. -->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>Namecoin DNS</title>
    <style type="text/css">
      body { margin: 0; padding: 0; }
      .lookup-form { max-width: 53em; 
        background-color: #D0D0D0;
        box-shadow: 0.4em 0.4em 0 #000000;
        font-family: monospace;
        float: right;
        margin-right: 1em;
      }
      .lookup-form p { margin-bottom: 0; }
      .lookup-form fieldset {
        border: solid #A0A0A0;
        border-width: 14px 7px 7px 7px;
        margin: 0;
      }
      .lookup-form legend {
        background-color: #C0C0C0;
        xcolor: #FFFFFF;
        font-weight: bold;
      }
      .lookup-form input[type="text"] {
        font-family: monospace;
      }
      #logo {
        transform: rotate(90deg) translateY(-4em) translateX(1.5em);
        transform-origin: left top;
        display: inline-block;
        position: absolute;
        top: 0;
        left: 0;
        opacity: .1;
        user-select: none;
        -moz-user-select: none;
        cursor: default;
      }
      #logo > div {
        font-family: "Trebuchet MS", sans-serif;
        font-size: 4em;
        text-shadow: 1px -1px #000000;
      }
      #logo1 {
        color: #111111;
        text-shadow: 1px -1px #000000;
      }
      
      #logo2, #logo3 {
        color: #666666;
      }
      #main {
        padding: 1em;
        padding-left: 3.5em;
      }
      #statusline {
        font-size: small;
        padding-top: 1em;
      }
      .rv { background-color: #E0E0E0; }
      .jsonField { width: 100%; box-sizing: border-box; }

      #navbar {
        background-color: #dddddd;
        padding-left: 3.15em;
      }
      #navbar ul, #navbar ul li { list-style: none; margin: 0; padding: 0; }
      #navbar ul li { display: inline-block; }
      #navbar ul li a { display: block; padding: 0.2em 0.5em 0.2em 0.5em; text-decoration: none; color: #000000; }
      #navbar ul li a:hover {
        color: #666666; }
      #imain { min-height: 80vh; }

      .testnotice {
        border: solid 0.5em #FF0000;
        background-color: #FFDDDD;
        padding: 1em;
        margin-bottom: 0.5em;
        font-weight: bold;
        font-size: 1.2em;
      }
    </style>
  </head>
  <body>
    <div id="logo"><div>
      {{.CanonicalSuffixHTML}}
    </div></div>
    <div id="navbar">
      <ul>
        <li><a href="/">{{.CanonicalSuffix}}</a></li>
        <li><a href="/lookup">Lookup Domain or Validate JSON</a></li>
      </ul>
    </div>
    <div id="main">
      <div id="imain">
        {{template "Main" .}}
      </div>
      <div id="statusline">
        Served by {{.SelfName}} at {{.Time}}
      </div>
    </div>
  </body>
</html>
