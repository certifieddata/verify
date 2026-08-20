// RFC 8785 — JSON Canonicalization Scheme (JCS).
// Hand-written so reviewers can confirm there is no surprise behavior.
//
// Rules summarized:
//   - Object keys are sorted lexicographically by their UTF-16 code-unit sequence.
//   - Strings are escaped using the minimal RFC 8259 §7 escapes (",\,\b,\f,\n,\r,\t)
//     plus \u00XX for any other control character (U+0000..U+001F).
//   - Numbers are emitted via the ECMAScript Number-to-String algorithm (ES2020
//     §7.1.12.1), which is what JSON.stringify already produces for finite numbers.
//     Non-finite numbers (NaN, ±Infinity) MUST NOT appear in canonical JSON.
//   - No insignificant whitespace anywhere.
//   - Arrays preserve insertion order; null/true/false serialize as their literals.
export function canonicalize(value) {
    return serialize(value);
}
export function canonicalizeToBytes(value) {
    return new TextEncoder().encode(canonicalize(value));
}
function serialize(value) {
    if (value === null)
        return "null";
    if (value === true)
        return "true";
    if (value === false)
        return "false";
    if (typeof value === "string")
        return serializeString(value);
    if (typeof value === "number")
        return serializeNumber(value);
    if (Array.isArray(value))
        return serializeArray(value);
    if (typeof value === "object")
        return serializeObject(value);
    throw new TypeError(`canonicalize: unsupported value of type ${typeof value}`);
}
function serializeArray(arr) {
    const parts = [];
    for (const item of arr)
        parts.push(serialize(item));
    return "[" + parts.join(",") + "]";
}
function serializeObject(obj) {
    // RFC 8785 §3.2.3: sort by UTF-16 code units. JS strings are UTF-16, and the
    // default Array#sort comparator on strings compares code-unit-by-code-unit, which
    // is exactly the JCS requirement.
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    const parts = [];
    for (const k of keys) {
        parts.push(serializeString(k) + ":" + serialize(obj[k]));
    }
    return "{" + parts.join(",") + "}";
}
function serializeNumber(n) {
    if (!Number.isFinite(n)) {
        throw new RangeError(`canonicalize: non-finite number ${n}`);
    }
    // ECMAScript Number-to-String, which JSON.stringify already invokes for finite
    // numbers. JCS aligns with this exact serialization.
    if (Object.is(n, -0))
        return "0";
    return JSON.stringify(n);
}
function serializeString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        switch (c) {
            case 0x22:
                out += '\\"';
                break;
            case 0x5c:
                out += "\\\\";
                break;
            case 0x08:
                out += "\\b";
                break;
            case 0x09:
                out += "\\t";
                break;
            case 0x0a:
                out += "\\n";
                break;
            case 0x0c:
                out += "\\f";
                break;
            case 0x0d:
                out += "\\r";
                break;
            default:
                if (c < 0x20) {
                    out += "\\u" + c.toString(16).padStart(4, "0");
                }
                else {
                    out += s[i];
                }
        }
    }
    return out + '"';
}
//# sourceMappingURL=canonicalize.js.map