"use strict";

(() => {
  function expandIPv6(raw) {
    const value = raw.trim().toLowerCase();
    if (!value || value.includes("%") || value.includes(".") ||
        !/^[0-9a-f:]+$/.test(value)) {
      throw Error("Enter an IPv6 address using hexadecimal groups");
    }

    const pieces = value.split("::");
    if (pieces.length > 2) throw Error("Invalid IPv6 compression");

    function parse(side) {
      if (!side) return [];
      const groups = side.split(":");
      if (groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) {
        throw Error("Invalid IPv6 group");
      }
      return groups;
    }

    const left = parse(pieces[0]);
    const right = pieces.length === 2 ? parse(pieces[1]) : [];
    const count = left.length + right.length;

    if (pieces.length === 1 && count !== 8) {
      throw Error("IPv6 requires eight groups without ::");
    }
    if (pieces.length === 2 && count >= 8) {
      throw Error("Invalid compressed IPv6 address");
    }

    const zeros = Array(8 - count).fill("0000");
    const groups = [...left, ...zeros, ...right]
      .map(g => g.padStart(4, "0"));

    return groups.join(":");
  }

  function inspectHeaders(raw) {
    if (!raw.trim()) throw Error("Paste HTTP response headers");

    const headers = new Map();
    for (const line of raw.split(/\r?\n/)) {
      const match = line.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+):\s*(.*)$/);
      if (match) {
        const key = match[1].toLowerCase();
        headers.set(key, [
          ...(headers.get(key) || []),
          match[2].trim()
        ]);
      }
    }

    if (!headers.size) throw Error("No valid HTTP headers found");

    const checks = [
      ["strict-transport-security", "HSTS"],
      ["content-security-policy", "Content Security Policy"],
      ["x-content-type-options", "Content-Type Protection"],
      ["referrer-policy", "Referrer Policy"],
      ["x-frame-options", "Frame Protection"]
    ];

    const lines = checks.map(([key, title]) =>
      `${headers.has(key) ? "FOUND" : "MISSING"} — ${title}` +
      (headers.has(key)
        ? `\n  ${headers.get(key).join("; ")}`
        : "")
    );

    if (headers.has("content-security-policy")) {
      const csp = headers.get("content-security-policy").join("; ");
      if (csp.includes("'unsafe-inline'")) {
        lines.push("\nNOTE: CSP permits unsafe-inline content.");
      }
    }

    lines.push(
      "\nPresence alone does not establish secure configuration.",
      "These checks do not verify browser behavior or policy strength."
    );

    return lines.join("\n\n");
  }

  function diffText(original, updated) {
    if (original === updated) return "No differences found.";

    const a = original.split("\n");
    const b = updated.split("\n");

    if (a.length > 500 || b.length > 500) {
      throw Error("Limit: 500 lines per text block");
    }

    const dp = Array.from(
      {length:a.length+1},
      () => new Uint16Array(b.length+1)
    );

    for (let i=a.length-1; i>=0; i--) {
      for (let j=b.length-1; j>=0; j--) {
        dp[i][j] = a[i] === b[j]
          ? dp[i+1][j+1]+1
          : Math.max(dp[i+1][j],dp[i][j+1]);
      }
    }

    const result = [];
    let i=0,j=0,added=0,removed=0;

    while(i<a.length || j<b.length) {
      if (i<a.length && j<b.length && a[i]===b[j]) {
        result.push("  "+a[i]);
        i++;j++;
      } else if (j<b.length &&
          (i===a.length || dp[i][j+1]>=dp[i+1][j])) {
        result.push("+ "+b[j++]);
        added++;
      } else {
        result.push("- "+a[i++]);
        removed++;
      }
    }

    return `Added lines: ${added}\nRemoved lines: ${removed}\n\n` +
      result.join("\n");
  }

  document.addEventListener("click", event => {
    const button = event.target.closest("[data-cx-advanced]");
    if (!button) return;

    const card = button.closest(".card");
    const output = card.querySelector(".output");

    try {
      let result;
      switch(button.dataset.cxAdvanced) {
        case "ipv6":
          result = expandIPv6(
            document.getElementById("cx-ipv6").value
          );
          break;
        case "headers":
          result = inspectHeaders(
            document.getElementById("cx-headers").value
          );
          break;
        case "diff":
          result = diffText(
            document.getElementById("cx-diff-original").value,
            document.getElementById("cx-diff-updated").value
          );
          break;
        default:
          return;
      }
      output.textContent = result;
    } catch(error) {
      output.textContent = "Error: " + error.message;
    }
  });
})();
