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
    /// bridge's one way out.
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
