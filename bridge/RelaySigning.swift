// How the watch and the Mac bridge prove a key to the relay without sending
// it, and how the watch checks the relay's answer — the one copy of both.
//
// An X-Tapproval-Signature header of "v1|v2 <unix time> <nonce> <hex
// HMAC-SHA256>", keyed by the key's UTF-8, over the method, the
// percent-decoded path, the query as sent (v2 only), the time, the nonce
// and the SHA-256 of the body — byte for byte what watch_relay.py's
// sign_request() makes. v1 left the query out, so a signed `?id=A` could be
// replayed as `?id=B` (2026-09-30 review). The bridge signs v2 always; the
// watch signs v2 once the relay holding its key has shown proof2.
//
// The watch and the bridge each kept their own copy until 2026-10-15, and
// a drift between them would have been a bridge or a watch whose every
// request was refused. This file is compiled into both targets, and the
// suite runs it, alone, against WatchApp/Shared/signing-vectors.json, which
// the relay itself regenerates. Keep it self-contained (Foundation and
// CryptoKit only) so that check can compile it without the rest.
import CryptoKit
import Foundation

enum RelaySigning {
    /// The MAC over one request. `query` nil is v1, which leaves it out.
    static func signature(key: String, method: String, path: String,
                                      query: String?, stamp: Int, nonce: String,
                                      body: Data) -> String {
        let message = ([method.uppercased(), path] + (query.map { [$0] } ?? [])
                       + [String(stamp), nonce, sha256(body)])
            .joined(separator: "\n")
        return mac(key, message)
    }

    /// The X-Tapproval-Signature value for `request`. v2 covers the query
    /// exactly as it goes on the wire — `?id=` names which thread is read.
    static func header(key: String, request: URLRequest, nonce: String,
                                   stamp: Int, v2: Bool) -> String {
        let query: String? = v2
            ? (request.url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false) }?
                .percentEncodedQuery ?? "")
            : nil
        let mac = signature(key: key, method: request.httpMethod ?? "GET",
                            path: request.url?.path ?? "/", query: query, stamp: stamp,
                            nonce: nonce, body: request.httpBody ?? Data())
        return "\(v2 ? "v2" : "v1") \(stamp) \(nonce) \(mac)"
    }

    /// A fresh nonce: 32 lowercase hex characters.
    static func nonce() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    /// `request`, signed v2 with `key` — or unchanged when there is no key,
    /// which the relay answers as it would any unproven local caller. The
    /// signing vectors check it against the relay (TestSigningVectors); the
    /// app and the bridge sign through header() in their proven paths.
    static func signed(_ request: URLRequest, key: String?,
                                   now: Date = Date()) -> URLRequest {
        guard let key, !key.isEmpty else { return request }
        var signed = request
        signed.setValue(header(key: key, request: request, nonce: nonce(),
                               stamp: Int(now.timeIntervalSince1970), v2: true),
                        forHTTPHeaderField: "X-Tapproval-Signature")
        return signed
    }

    /// The relay's first proof (relay_proof): names only the nonce.
    static func proof(key: String, nonce: String) -> String {
        mac(key, "tapproval-proof\n\(nonce)")
    }

    /// The relay's second proof (relay_proof2): the nonce, the status and
    /// the SHA-256 of the answer's body.
    static func proof2(key: String, nonce: String, status: Int,
                                   body: Data) -> String {
        mac(key, "tapproval-proof2\n\(nonce)\n\(status)\n\(sha256(body))")
    }

    /// A key the relay sealed for the holder of `key` (seal), or nil.
    static func unseal(_ sealed: String, key: String, nonce: String) -> String? {
        let pad = Data(HMAC<SHA256>.authenticationCode(
            for: Data("tapproval-seal\n\(nonce)".utf8),
            using: SymmetricKey(data: Data(key.utf8))))
        var bytes: [UInt8] = []
        var index = sealed.startIndex
        while index < sealed.endIndex {
            let next = sealed.index(index, offsetBy: 2, limitedBy: sealed.endIndex) ?? sealed.endIndex
            guard let byte = UInt8(sealed[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        guard bytes.count <= pad.count else { return nil }
        return String(bytes: zip(bytes, pad).map { $0 ^ $1 }, encoding: .utf8)
    }

    private static func mac(_ key: String, _ message: String) -> String {
        hex(HMAC<SHA256>.authenticationCode(for: Data(message.utf8),
                                            using: SymmetricKey(data: Data(key.utf8))))
    }

    private static func sha256(_ data: Data) -> String {
        hex(SHA256.hash(data: data))
    }

    private static func hex<D: Sequence>(_ bytes: D) -> String
        where D.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// The travel road's bodies, sealed end to end (#645): ChaCha20-Poly1305
/// under a key derived from this watch's own key (HKDF-SHA256, the same
/// derivation as tapproval_wire.seal_key on the computer, checked byte for
/// byte in both test suites). Cloudflare's edge, where the tunnel's TLS
/// ends, carries bytes only this watch and its computer can read.
enum BodySeal {
    static let header = "X-Tapproval-Sealed"
    /// Set on the answer the callers see when it came in an envelope.
    static let envelopedField = "X-Tapproval-Enveloped"
    private static let info = Data("tapproval-seal-v1".utf8)

    /// The travel tunnel only: the home road is TLS to the computer itself.
    static func applies(to url: URL?) -> Bool {
        (url?.host ?? "").hasSuffix(".trycloudflare.com")
    }

    static func key(_ deviceKey: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(deviceKey.utf8)),
                               info: info, outputByteCount: 32)
    }

    /// Bound to the method and path, so a sealed body cannot be moved to
    /// another route; an answer's words differ from its question's.
    static func aad(_ method: String, _ path: String, answer: Bool = false) -> Data {
        Data(((answer ? "answer " : "") + method.uppercased() + " " + path).utf8)
    }

    static func seal(_ body: Data, deviceKey: String, aad: Data) throws -> Data {
        try ChaChaPoly.seal(body, using: key(deviceKey), authenticating: aad).combined
    }

    static func open(_ sealed: Data, deviceKey: String, aad: Data) -> Data? {
        guard let box = try? ChaChaPoly.SealedBox(combined: sealed) else { return nil }
        return try? ChaChaPoly.open(box, using: key(deviceKey), authenticating: aad)
    }

    // The envelope (#645 phase 3): the whole request in one sealed body, as
    // tapproval_wire.wrap_request writes it, so Cloudflare's edge reads
    // neither the route, the query nor the answer's status.
    static let envelopeAAD = Data("POST /e".utf8)
    static let envelopeAnswerAAD = Data("answer POST /e".utf8)

    /// `…/t/<secret>/pending?x` → `…/t/<secret>/e`; nil off the tunnel.
    static func envelopeURL(for url: URL) -> URL? {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let range = parts.path.range(of: #"^/t/[^/]+"#, options: .regularExpression)
        else { return nil }
        parts.path = String(parts.path[range]) + "/e"
        parts.query = nil
        return parts.url
    }

    /// The route after the tunnel's `/t/<secret>` prefix.
    static func innerPath(_ url: URL) -> String {
        let path = url.path
        guard let range = path.range(of: #"^/t/[^/]+"#, options: .regularExpression) else { return path }
        let rest = String(path[range.upperBound...])
        return rest.isEmpty ? "/" : rest
    }

    static func wrapRequest(method: String, path: String, query: String, body: Data) -> Data {
        let inner: [String: String] = ["m": method.uppercased(), "p": path, "q": query,
                                       "b": body.base64EncodedString()]
        return (try? JSONSerialization.data(withJSONObject: inner, options: [.sortedKeys])) ?? Data()
    }

    static func unwrapAnswer(_ data: Data) -> (Int, Data)? {
        guard let inner = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let status = inner["s"] as? Int,
              let body = Data(base64Encoded: inner["b"] as? String ?? "")
        else { return nil }
        return (status, body)
    }
}
