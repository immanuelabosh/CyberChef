/**
 * HAProxy Dynamic Cookie tests
 *
 * Reference values were cross-checked against HAProxy's srv_set_dyncookie()
 * algorithm using the xxhash-wasm library, and date fields against a build of
 * HAProxy's s30tob64().
 *
 * @author immanuelabosh
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

const KEY = { option: "UTF8", string: "mysecretkey" };

TestRegister.addTests([
    {
        name: "HAProxy Dynamic Cookie: ip:port",
        input: "10.0.0.1:8080",
        expectedOutput: "9dc3ee63bcef8674",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: several servers, blank lines, comments, CRLF",
        input: "# backend web\r\n10.2.126.17:80\r\n\r\n  10.2.126.18 80\r\n10.2.126.19:80\r\n",
        expectedOutput: "1c8baf76a7297f69\na4a12c6ba711ec0b\ndb1d614a1ce376ce",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: IPv6 bracketed and bare",
        input: "[2001:db8::1]:443\n::1 80\nipv6@[2001:db8::1]:443",
        expectedOutput: "3438d656124473ec\n7e709dd121c426ae\n3438d656124473ec",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: missing port hashes as port 0",
        input: "10.0.0.1\nipv4@10.0.0.1",
        expectedOutput: "e80c286b8afd83ec\ne80c286b8afd83ec",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: hex key",
        input: "10.0.0.1:80",
        expectedOutput: "51155f4c8d446125",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [{ option: "Hex", string: "00ff" }, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: empty key",
        input: "10.0.0.1:80",
        expectedOutput: "a8de94c1e23c41fe",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [{ option: "UTF8", string: "" }, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: pasted backend, explicit cookie wins",
        input: "backend web\n    balance roundrobin\n    cookie SRV insert indirect nocache dynamic\n    dynamic-cookie-key othersecret\n    default-server inter 2s\n    server web1 10.2.126.17:80 check\n    server web2 10.2.126.18:80 check cookie static2\n    server web3 10.2.126.19:80 weight 10",
        expectedOutput: "web1 1c8baf76a7297f69\nweb2 static2\nweb3 db1d614a1ce376ce",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Name or address and cookie", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: key taken from dynamic-cookie-key when argument is blank",
        input: "backend web\n    cookie SRV insert dynamic\n    dynamic-cookie-key \"mysecretkey\"\n    server web1 10.2.126.17:80 check\n    server web2 10.2.126.18:80 check",
        expectedOutput: "1c8baf76a7297f69\na4a12c6ba711ec0b",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [{ option: "UTF8", string: "" }, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: key argument overrides dynamic-cookie-key",
        input: "dynamic-cookie-key othersecret\nserver web1 10.2.126.17:80",
        expectedOutput: "1c8baf76a7297f69",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: address and cookie output",
        input: "10.0.0.1:8080\n[::1]:80",
        expectedOutput: "10.0.0.1:8080 9dc3ee63bcef8674\n[::1]:80 7e709dd121c426ae",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Name or address and cookie", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: server line output from server statements",
        input: "server web1 10.2.126.17:80 check\nserver web2 10.2.126.18:80 cookie static2",
        expectedOutput: "server web1 10.2.126.17:80 check cookie 1c8baf76a7297f69\nserver web2 10.2.126.18:80 cookie static2",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "HAProxy server line", "maxlife (|last|first)", "1791331200"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: server line output from addresses",
        input: "10.2.126.17:80\n[2001:db8::1]:443",
        expectedOutput: "server srv1 10.2.126.17:80 cookie 1c8baf76a7297f69\nserver srv2 [2001:db8::1]:443 cookie 3438d656124473ec",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "HAProxy server line", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: maxidle date field",
        input: "10.0.0.1:8080",
        expectedOutput: "9dc3ee63bcef8674|asWLg",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxidle (|last)", "1791331200"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: maxlife date fields from ISO date",
        input: "10.0.0.1:8080",
        expectedOutput: "9dc3ee63bcef8674|asWLg|asWLg",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxlife (|last|first)", "2026-10-07T00:00:00Z"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: date field edge values",
        input: "server a 10.0.0.1:80 cookie X",
        expectedOutput: "X|ZVPxA",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxidle (|last)", "1700000000"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: date field wraps at 30 bits",
        input: "server a 10.0.0.1:80 cookie X",
        expectedOutput: "X|gAAAA",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxidle (|last)", "2147483647"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: date field with current time has valid shape",
        input: "10.0.0.1:8080",
        expectedMatch: /^9dc3ee63bcef8674\|[A-Za-z0-9+/]{5}$/,
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxidle (|last)", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: invalid date",
        input: "10.0.0.1:8080",
        expectedOutput: "Could not parse date 'yesterday'. Use UNIX seconds or an ISO 8601 timestamp.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "maxidle (|last)", "yesterday"] }],
    },
    {
        name: "HAProxy Dynamic Cookie: hostname rejected",
        input: "10.0.0.1:80\nweb1.example.com:80",
        expectedOutput: "Line 2: 'web1.example.com' is not an IPv4 or IPv6 address. HAProxy hashes the resolved address, so hostnames must be resolved first.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: unix socket rejected",
        input: "server app unix@/var/run/app.sock",
        expectedOutput: "Line 1: 'unix@/var/run/app.sock' has no IP address. HAProxy only generates dynamic cookies for IPv4 and IPv6 servers.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: invalid port",
        input: "10.0.0.1:70000",
        expectedOutput: "Line 1: '70000' is not a valid port. Port offsets and ranges are not supported.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: invalid IPv4 octet",
        input: "10.0.0.256:80",
        expectedOutput: "Line 1: '10.0.0.256' is not a valid IPv4 address.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: unparseable line",
        input: "10.0.0.1:80 extra junk",
        expectedOutput: "Line 1: could not parse '10.0.0.1:80 extra junk'. Expected 'ip:port', '[ipv6]:port', 'ip port' or an HAProxy 'server' statement.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: named line without the server keyword is an error",
        input: "web1 10.0.0.1:80",
        expectedOutput: "Line 1: could not parse 'web1 10.0.0.1:80'. Expected 'ip:port', '[ipv6]:port', 'ip port' or an HAProxy 'server' statement.",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: mixed input formats on consecutive lines",
        input: "server au2wp-ssb-401 10.2.126.17:80\n10.2.126.18:80\n10.2.126.19 80\n[2001:db8::1]:443\n2001:db8::1 443\nipv4@10.2.126.17:80\n10.2.126.17",
        expectedOutput: "au2wp-ssb-401 1c8baf76a7297f69\n10.2.126.18:80 a4a12c6ba711ec0b\n10.2.126.19:80 db1d614a1ce376ce\n[2001:db8::1]:443 3438d656124473ec\n[2001:db8::1]:443 3438d656124473ec\n10.2.126.17:80 1c8baf76a7297f69\n10.2.126.17:0 5711772212fc27d6",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Name or address and cookie", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: mixed formats interleaved with configuration lines",
        input: "backend web\n    balance roundrobin\n    cookie SRV insert indirect nocache dynamic\n    dynamic-cookie-key \"mysecretkey\"\n    default-server inter 2s\n    server web1 10.2.126.17:80 check\n10.2.126.18:80\n    # a comment\n10.2.126.19 80\n    server web4 10.2.126.18:80 cookie fixed",
        expectedOutput: "1c8baf76a7297f69\na4a12c6ba711ec0b\ndb1d614a1ce376ce\nfixed",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [{ option: "UTF8", string: "" }, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: configuration keywords without any server statement are ignored",
        input: "defaults\nmode http\ntimeout connect 5s\n10.0.0.1:8080",
        expectedOutput: "9dc3ee63bcef8674",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
    {
        name: "HAProxy Dynamic Cookie: empty input",
        input: "",
        expectedOutput: "",
        recipeConfig: [{ op: "HAProxy Dynamic Cookie", args: [KEY, "Cookie value", "None", ""] }],
    },
]);
