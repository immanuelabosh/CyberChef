/**
 * @author immanuelabosh
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import XXH64 from "./XXH64.mjs";
import { IPV4_REGEX, IPV6_REGEX, strToIpv6 } from "../lib/IP.mjs";

/** Alphabet used by HAProxy's s30tob64() for cookie date fields. */
const BASE64_TAB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Separator HAProxy places between the server cookie and its date fields. */
const COOKIE_DELIM_DATE = "|";

/** HAProxy address prefixes that never yield a dynamic cookie (no IP address). */
const NON_IP_PREFIX = /^(unix|abns|abnsz|sockpair|fd|rhttp)@/i;

/**
 * HAProxy Dynamic Cookie operation
 */
class HAProxyDynamicCookie extends Operation {

    /**
     * HAProxyDynamicCookie constructor
     */
    constructor() {
        super();

        this.name = "HAProxy Dynamic Cookie";
        this.module = "Hashing";
        this.description = "Calculates the persistence cookie values that HAProxy assigns to backend servers when dynamic cookies are enabled (<code>cookie &lt;name&gt; insert ... dynamic</code> together with <code>dynamic-cookie-key &lt;secret&gt;</code>).<br><br>HAProxy derives each server's cookie as the XXH64 hash (seed 0) of the secret key followed by the server's IP address (4 bytes for IPv4, 16 bytes for IPv6) and its port as a 32-bit big-endian integer, rendered as 16 lowercase hexadecimal characters. Servers that declare an explicit <code>cookie</code> parameter keep that value instead, and dynamic cookies are only generated for servers with an IPv4 or IPv6 address.<br><br>Enter one server per line as <code>ip:port</code>, <code>[ipv6]:port</code> or <code>ip port</code>, or paste <code>server</code> statements straight from an HAProxy configuration. A missing port is treated as 0, as HAProxy does. Blank lines and comments are ignored. When the input contains <code>server</code> statements, all other configuration lines are ignored too, and a <code>dynamic-cookie-key</code> line supplies the key if the key argument is left blank, so an entire backend section can be pasted as-is.<br><br>When <code>maxidle</code> or <code>maxlife</code> are configured, HAProxy appends the last-seen date and, for maxlife, the first-seen date to the cookie as <code>|</code>-separated 5-character base64 values of the UNIX time in 4-second units. The Date fields option reproduces that suffix for the given date.";
        this.infoURL = "https://docs.haproxy.org/3.2/configuration.html#dynamic-cookie-key";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Secret key (dynamic-cookie-key)",
                type: "toggleString",
                value: "",
                toggleValues: ["UTF8", "Hex", "Latin1", "Base64"]
            },
            {
                name: "Output format",
                type: "option",
                value: ["Cookie value", "Name or address and cookie", "HAProxy server line"]
            },
            {
                name: "Date fields",
                type: "option",
                value: ["None", "maxidle (|last)", "maxlife (|last|first)"]
            },
            {
                name: "Date (UNIX seconds or ISO 8601, blank = now)",
                type: "string",
                value: ""
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [key, outputFormat, dateFields, dateStr] = args;
        const lines = input.split(/\r?\n/).map(l => l.trim());

        // Configuration mode: when 'server' statements are present, every other
        // line is treated as surrounding configuration and ignored.
        const configMode = lines.some(l => /^server\s/.test(l));
        let keyBytes = Uint8Array.from(Utils.convertToByteArray(key.string || "", key.option));
        if (configMode && keyBytes.length === 0) {
            const keyLine = lines.find(l => /^dynamic-cookie-key\s/.test(l));
            if (keyLine) {
                keyBytes = Utils.strToUtf8ByteArray(HAProxyDynamicCookie.unquote(keyLine.replace(/^dynamic-cookie-key\s+/, "")));
            }
        }

        let dateSuffix = "";
        if (dateFields !== "None" && outputFormat !== "HAProxy server line") {
            const encoded = HAProxyDynamicCookie.s30tob64(Math.floor((HAProxyDynamicCookie.parseDate(dateStr) + 3) / 4));
            dateSuffix = COOKIE_DELIM_DATE + encoded;
            if (dateFields.startsWith("maxlife")) dateSuffix += COOKIE_DELIM_DATE + encoded;
        }

        const output = [];
        let generated = 0;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line === "" || line.startsWith("#")) continue;
            if (configMode && !/^server\s/.test(line)) continue;

            const server = HAProxyDynamicCookie.parseLine(line, i + 1);
            if (server === null) continue;
            generated++;

            const cookie = server.staticCookie !== null ?
                server.staticCookie :
                HAProxyDynamicCookie.computeCookie(keyBytes, server.addrBytes, server.port);

            switch (outputFormat) {
                case "Name or address and cookie":
                    output.push(`${server.name !== null ? server.name : server.address} ${cookie}${dateSuffix}`);
                    break;
                case "HAProxy server line":
                    if (server.statement !== null) {
                        output.push(server.staticCookie !== null ? server.statement : `${server.statement} cookie ${cookie}`);
                    } else {
                        output.push(`server srv${generated} ${server.address} cookie ${cookie}`);
                    }
                    break;
                default:
                    output.push(cookie + dateSuffix);
            }
        }

        return output.join("\n");
    }

    /**
     * Parses one input line into a server description.
     *
     * @param {string} line - trimmed, non-empty line
     * @param {number} lineNo - 1-based line number for error messages
     * @returns {?Object} null if the line carries no server (e.g. default-server)
     */
    static parseLine(line, lineNo) {
        const tokens = line.split(/\s+/);
        let name = null,
            addrToken,
            params = [],
            statement = null;

        if (tokens[0] === "server") {
            if (tokens.length < 3) {
                throw new OperationError(`Line ${lineNo}: a 'server' statement needs a name and an address.`);
            }
            name = tokens[1];
            addrToken = tokens[2];
            params = tokens.slice(3);
            statement = line;
        } else if (tokens[0] === "default-server") {
            return null;
        } else if (tokens.length === 1) {
            addrToken = tokens[0];
        } else if (tokens.length === 2 && /^\d{1,5}$/.test(tokens[1])) {
            addrToken = tokens[0].includes(":") && !tokens[0].startsWith("[") ?
                `[${tokens[0]}]:${tokens[1]}` :
                `${tokens[0]}:${tokens[1]}`;
        } else {
            throw new OperationError(`Line ${lineNo}: could not parse '${line}'. Expected 'ip:port', '[ipv6]:port', 'ip port' or an HAProxy 'server' statement.`);
        }

        let staticCookie = null;
        const cookieIdx = params.indexOf("cookie");
        if (cookieIdx !== -1) {
            if (cookieIdx + 1 >= params.length) {
                throw new OperationError(`Line ${lineNo}: 'cookie' parameter has no value.`);
            }
            staticCookie = params[cookieIdx + 1];
        }

        const addr = HAProxyDynamicCookie.parseAddress(addrToken, lineNo);
        return { name, statement, staticCookie, ...addr };
    }

    /**
     * Parses an HAProxy server address token such as 10.0.0.1:80, [::1]:443,
     * ipv4@10.0.0.1 or 10.0.0.1 into raw address bytes and a port.
     *
     * @param {string} token
     * @param {number} lineNo
     * @returns {{address: string, addrBytes: Uint8Array, port: number}}
     */
    static parseAddress(token, lineNo) {
        if (NON_IP_PREFIX.test(token)) {
            throw new OperationError(`Line ${lineNo}: '${token}' has no IP address. HAProxy only generates dynamic cookies for IPv4 and IPv6 servers.`);
        }
        const addr = token.replace(/^(ipv4|ipv6|tcp4|tcp6|udp4|udp6|quic4|quic6)@/i, "");

        let host,
            portStr = null;
        if (addr.startsWith("[")) {
            const m = /^\[([^\]]+)\](?::(.*))?$/.exec(addr);
            if (!m) throw new OperationError(`Line ${lineNo}: malformed bracketed address '${addr}'.`);
            host = m[1];
            portStr = m[2] !== undefined ? m[2] : null;
        } else {
            const idx = addr.lastIndexOf(":");
            if (idx !== -1 && addr.indexOf(":") === idx) {
                host = addr.slice(0, idx);
                portStr = addr.slice(idx + 1);
            } else {
                host = addr;
            }
        }

        let port = 0;
        if (portStr !== null && portStr !== "") {
            if (!/^\d{1,5}$/.test(portStr) || parseInt(portStr, 10) > 65535) {
                throw new OperationError(`Line ${lineNo}: '${portStr}' is not a valid port. Port offsets and ranges are not supported.`);
            }
            port = parseInt(portStr, 10);
        }

        let addrBytes;
        if (IPV4_REGEX.test(host)) {
            const octets = host.trim().split(".").map(o => parseInt(o, 10));
            if (octets.some(o => o > 255)) {
                throw new OperationError(`Line ${lineNo}: '${host}' is not a valid IPv4 address.`);
            }
            addrBytes = Uint8Array.from(octets);
            return { address: `${host.trim()}:${port}`, addrBytes, port };
        }
        if (IPV6_REGEX.test(host) && !host.includes(".")) {
            addrBytes = new Uint8Array(16);
            strToIpv6(host.trim()).forEach((word, i) => {
                addrBytes[2 * i] = word >>> 8;
                addrBytes[2 * i + 1] = word & 0xff;
            });
            return { address: `[${host.trim()}]:${port}`, addrBytes, port };
        }
        throw new OperationError(`Line ${lineNo}: '${host}' is not an IPv4 or IPv6 address. HAProxy hashes the resolved address, so hostnames must be resolved first.`);
    }

    /**
     * Computes the dynamic cookie exactly as HAProxy's srv_set_dyncookie():
     * XXH64(key || address bytes || htonl(port), seed 0) printed with %016llx.
     *
     * @param {Uint8Array} keyBytes
     * @param {Uint8Array} addrBytes
     * @param {number} port
     * @returns {string}
     */
    static computeCookie(keyBytes, addrBytes, port) {
        const buf = new Uint8Array(keyBytes.length + addrBytes.length + 4);
        buf.set(keyBytes, 0);
        buf.set(addrBytes, keyBytes.length);
        new DataView(buf.buffer).setUint32(keyBytes.length + addrBytes.length, port, false);
        return XXH64.hash(buf, 0n).toString(16).padStart(16, "0");
    }

    /**
     * Encodes the low 30 bits of a number as 5 base64 characters, MSB first,
     * matching HAProxy's s30tob64().
     *
     * @param {number} value
     * @returns {string}
     */
    static s30tob64(value) {
        let v = value % 0x40000000;
        let out = "";
        for (let i = 0; i < 5; i++) {
            out += BASE64_TAB[(v >>> 24) & 0x3f];
            v = (v << 6) & 0x3fffffff;
        }
        return out;
    }

    /**
     * Removes one level of surrounding single or double quotes, as used in
     * HAProxy configuration values.
     *
     * @param {string} value
     * @returns {string}
     */
    static unquote(value) {
        const v = value.trim();
        if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
            return v.slice(1, -1);
        }
        return v;
    }

    /**
     * Parses the date argument into UNIX seconds.
     *
     * @param {string} str - blank for now, digits for UNIX seconds, otherwise ISO 8601
     * @returns {number}
     */
    static parseDate(str) {
        const s = (str || "").trim();
        if (s === "") return Math.floor(Date.now() / 1000);
        if (/^\d+$/.test(s)) return parseInt(s, 10);
        const ms = Date.parse(s);
        if (isNaN(ms)) {
            throw new OperationError(`Could not parse date '${s}'. Use UNIX seconds or an ISO 8601 timestamp.`);
        }
        return Math.floor(ms / 1000);
    }

}

export default HAProxyDynamicCookie;
