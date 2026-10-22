"use strict";

document.addEventListener("click", async event => {
  const button = event.target.closest("[data-cx-tool]");
  if (!button) return;

  const card = button.closest(".card");
  const output = card.querySelector(".output");
  const action = button.dataset.cxTool;
  const value = id => document.getElementById(id).value.trim();

  const httpCodes = {
    200:"OK",201:"Created",202:"Accepted",
    204:"No Content",301:"Moved Permanently",
    302:"Found",304:"Not Modified",
    307:"Temporary Redirect",308:"Permanent Redirect",
    400:"Bad Request",401:"Unauthorized",
    403:"Forbidden",404:"Not Found",
    405:"Method Not Allowed",408:"Request Timeout",
    409:"Conflict",410:"Gone",418:"I'm a Teapot",
    422:"Unprocessable Content",429:"Too Many Requests",
    500:"Internal Server Error",501:"Not Implemented",
    502:"Bad Gateway",503:"Service Unavailable",
    504:"Gateway Timeout"
  };

  const ports = {
    "20":"FTP data (TCP)",
    "21":"FTP control (TCP)",
    "22":"SSH / SFTP (TCP)",
    "23":"Telnet (TCP)",
    "25":"SMTP (TCP)",
    "53":"DNS (TCP/UDP)",
    "67":"DHCP server (UDP)",
    "68":"DHCP client (UDP)",
    "80":"HTTP (TCP)",
    "110":"POP3 (TCP)",
    "123":"NTP (UDP)",
    "143":"IMAP (TCP)",
    "161":"SNMP (UDP)",
    "389":"LDAP (TCP/UDP)",
    "443":"HTTPS (TCP); HTTP/3 commonly uses UDP",
    "445":"SMB (TCP)",
    "465":"SMTPS (TCP)",
    "587":"SMTP submission (TCP)",
    "636":"LDAPS (TCP)",
    "993":"IMAPS (TCP)",
    "995":"POP3S (TCP)",
    "1433":"Microsoft SQL Server (TCP)",
    "3306":"MySQL (TCP)",
    "3389":"RDP (TCP/UDP)",
    "5432":"PostgreSQL (TCP)",
    "5900":"VNC (TCP)",
    "6379":"Redis (TCP)",
    "8080":"Alternate HTTP (TCP)"
  };

  function jwtPart(part) {
    const normalized = part.replace(/-/g,"+").replace(/_/g,"/");
    const binary = atob(normalized.padEnd(
      Math.ceil(normalized.length / 4) * 4, "="
    ));
    return JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(
      Uint8Array.from(binary, c => c.charCodeAt(0))
    ));
  }

  try {
    let result = "";

    switch (action) {
      case "ip": {
        const ip = value("cx-ip");
        const parts = ip.split(".");
        if (parts.length !== 4 ||
            parts.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || +p > 255)) {
          throw Error("Enter a valid IPv4 address");
        }
        const [a,b] = parts.map(Number);
        let kind = "Not in a commonly reserved range";
        if (a === 10 || (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168))
          kind = "Private (RFC 1918)";
        else if (a === 127) kind = "Loopback";
        else if (a === 169 && b === 254) kind = "Link-local";
        else if (a >= 224 && a <= 239) kind = "Multicast";
        else if (a >= 240) kind = "Reserved / special-purpose";
        else if (a === 0 || (a === 100 && b >= 64 && b <= 127) ||
          (a === 192 && b === 0) ||
          (a === 192 && b === 0 && +parts[2] === 2) ||
          (a === 198 && [18,19,51].includes(b)) ||
          (a === 203 && b === 0))
          kind = "Special-purpose / non-public";
        result = `${ip}\nClassification: ${kind}\nIPv4 address`;
        break;
      }

      case "json-pretty":
        result = JSON.stringify(JSON.parse(value("cx-json")), null, 2);
        break;
      case "json-mini":
        result = JSON.stringify(JSON.parse(value("cx-json")));
        break;

      case "url-encode":
        result = encodeURIComponent(document.getElementById("cx-url").value);
        break;
      case "url-decode":
        result = decodeURIComponent(value("cx-url"));
        break;

      case "jwt": {
        const parts = value("cx-jwt").split(".");
        if (parts.length !== 3) throw Error("Expected a three-part JWT");
        const header = jwtPart(parts[0]);
        const payload = jwtPart(parts[1]);
        result = "HEADER\n" + JSON.stringify(header,null,2)
          + "\n\nPAYLOAD\n" + JSON.stringify(payload,null,2);
        if (typeof payload.exp === "number") {
          result += "\n\nExpires: " +
            new Date(payload.exp*1000).toISOString();
        }
        result += "\n\nUNVERIFIED — signature not checked";
        break;
      }

      case "hex-encode":
        result = Array.from(new TextEncoder().encode(
          document.getElementById("cx-hex").value
        )).map(x=>x.toString(16).padStart(2,"0")).join(" ");
        break;
      case "hex-decode": {
        const hex = value("cx-hex").replace(/\s+/g,"");
        if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex))
          throw Error("Use complete hexadecimal byte pairs");
        const bytes = Uint8Array.from(
          hex.match(/.{2}/g) || [], x => parseInt(x,16)
        );
        result = new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        break;
      }

      case "sha512": {
        const bytes = new TextEncoder().encode(
          document.getElementById("cx-sha512").value
        );
        const digest = await crypto.subtle.digest("SHA-512",bytes);
        result = Array.from(new Uint8Array(digest))
          .map(b=>b.toString(16).padStart(2,"0")).join("");
        break;
      }

      case "http": {
        const q = value("cx-http");
        result = httpCodes[q]
          ? `${q} — ${httpCodes[q]}`
          : "Code not in the built-in reference";
        break;
      }

      case "port": {
        const q = value("cx-port").toLowerCase();
        const matches = Object.entries(ports).filter(
          ([port,description]) =>
            port === q || description.toLowerCase().includes(q)
        );
        result = q && matches.length
          ? matches.map(([p,d])=>`${p} — ${d}`).join("\n")
          : "No matching port in the built-in reference";
        break;
      }

      default: return;
    }

    output.textContent = result || "(empty result)";
  } catch (error) {
    output.textContent = "Error: " + error.message;
  }
});
