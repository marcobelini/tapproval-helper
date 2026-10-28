// TapprovalBridge — mirrors the local relay's pending cards into the
// user's private CloudKit database and carries decisions back, so the watch
// works anywhere, not just on the home Wi-Fi.
//
// Runs as a faceless agent on the Mac next to watch_relay.py. The relay
// stays the single integration point for the Claude Code hook; this bridge
// is a thin adapter on top of its HTTP API.
import CloudKit
import Foundation
import Security
import ServiceManagement

// The login item (1.1.0). The bridge registers its own, from the job file
// sealed inside this signed app (Contents/Library/LaunchAgents), so System
// Settings → Login Items lists it as "Tapproval" with the App Store logo.
// A job file the helper wrote into ~/Library/LaunchAgents was listed under
// the name on the signing certificate — the developer's legal name —
// whatever it said (tested 2026-10-24). Only an app can register itself, so
// the helper's installer asks through these switches, and reads the one
// word printed first: enabled, requires-approval (the user switched it off
// in Login Items), not-registered or not-found.
let loginItem = SMAppService.agent(plistName: "com.tapproval.bridge.plist")

func loginWord(_ status: SMAppService.Status) -> String {
    switch status {
    case .enabled: return "enabled"
    case .requiresApproval: return "requires-approval"
    case .notRegistered: return "not-registered"
    case .notFound: return "not-found"
    @unknown default: return "unknown"
    }
}

if let flag = CommandLine.arguments.dropFirst().first,
   ["--register", "--unregister", "--login-status"].contains(flag) {
    var failure: Error?
    do {
        if flag == "--register" { try loginItem.register() }
        if flag == "--unregister" { try loginItem.unregister() }
    } catch {
        failure = error
    }
    print(loginWord(loginItem.status))
    if let failure {
        FileHandle.standardError.write(Data("\(flag): \(failure.localizedDescription)\n".utf8))
    }
    // A register refused because the user switched Tapproval off is their
    // choice kept, not a failure.
    exit(failure == nil || loginItem.status == .requiresApproval ? 0 : 1)
}

let relayBase = URL(string: "http://127.0.0.1:8977")!
let database = CKContainer(identifier: "iCloud.app.tapproval")
    .privateCloudDatabase

/// Every CloudKit call goes through here, bounded. CloudKit's own default
/// waits a minute on a quiet connection, and one hung save used to hold the
/// whole tick, cards and answers alike (2026-10-16 review, L3).
func cloud<R>(_ body: (CKDatabase) async throws -> R) async throws -> R {
    let configuration = CKOperation.Configuration()
    configuration.timeoutIntervalForRequest = 10
    configuration.timeoutIntervalForResource = 20
    configuration.qualityOfService = .userInitiated
    return try await database.configuredWith(configuration: configuration, body: body)
}

struct Card: Codable { let id: String; let tier: String
    let headline: String; let detail: String; let project: String?
    // Question cards: "question" plus the phone app's exact option
    // labels. Stripping these would demote a question to a bare
    // permission card on the watch.
    let kind: String?; let options: [String]?
    // What a notification on a closed watch may offer ("go", "careful",
    // "stop", "ask"), decided by the relay's alert_bucket(). Absent from a
    // relay older than it, and then the strictest reading stands.
    let alert: String?
    // The rest of what the watch shows: a plan card's plan, the facts
    // chosen for an unknown tool, which session asked, and whether the
    // phone offers "don't ask again". Carried since 2026-09-30; a card
    // that came through iCloud used to arrive without them.
    let plan: String?; let facts: [[String]]?
    let sessionID: String?; let canAlways: Bool?
    // The session's title beside the repository on the wrist's place line,
    // added by the relay (helper 1.1.35). Install a bridge carrying it only
    // after `sessionTitle` is in the Production schema (RELEASING.md).
    let sessionTitle: String?
    // A plan card's plan with its bold and headings kept (helper 1.1.44).
    // Install a bridge carrying it only after `planMarked` is in the
    // Production schema (RELEASING.md).
    let planMarked: String?
    // Another agent's own words for allow and deny (helper 1.1.51). Install
    // a bridge carrying them only after `allowLabel` and `denyLabel` are in
    // the Production schema (RELEASING.md).
    let allowLabel: String?; let denyLabel: String?
    // Which agent asked: "codex", or absent for Claude Code (M2 of #390).
    // Install a bridge carrying it only after `agent` is in the Production
    // schema (RELEASING.md).
    let agent: String?
    // A question that takes several answers (helper 1.1.56). Install a
    // bridge carrying it only after `multiSelect` is in the Production
    // schema (RELEASING.md).
    let multiSelect: Bool?
    // A question's heading chip and each option's explanation (#610).
    // Install a bridge carrying them only after `questionHeader` and
    // `optionDetails` are in the Production schema (RELEASING.md).
    let questionHeader: String?; let optionDetails: [String]?
    var alertBucket: String { alert ?? (kind == "question" ? "ask" : "stop") }
    enum CodingKeys: String, CodingKey {
        case id, tier, headline, detail, project, kind, options, alert, plan, facts
        case sessionID = "session_id"
        case sessionTitle = "session_title"
        case canAlways = "can_always"
        case planMarked = "plan_marked"
        case allowLabel = "allow_label"
        case denyLabel = "deny_label"
        case agent
        case multiSelect = "multi_select"
        case questionHeader = "question_header"
        case optionDetails = "option_details"
    } }
struct Pending: Codable { let cards: [Card] }

var mirrored: Set<String> = []
/// CloudKit save refusals in a row, and what the last one said. Three in a
/// row are a condition on the wrist, through /bridge-status; until then a
/// refusal is a blip. While refused, new saves wait for the server's
/// retry-after (or 30 s) instead of every card every 2 s, which told nobody
/// and grew the log (2026-10-25 review).
var saveFailures = 0
var lastSaveError = ""
var savesHeldUntil = Date.distantPast
/// A refusal that is about one record — a field the Production schema does
/// not know, say — waits for that card alone. Holding every save for it
/// kept each card behind it off iCloud for as long as it stayed pending
/// (2026-10-26 review).
var cardHeldUntil: [String: Date] = [:]

/// Is this refusal iCloud's as a whole (busy, throttled, offline, signed
/// out, full), or one record's? Only the first holds every save.
func holdsEverySave(_ error: Error) -> Bool {
    guard let error = error as? CKError else { return true }
    if error.retryAfterSeconds != nil { return true }
    switch error.code {
    case .requestRateLimited, .zoneBusy, .serviceUnavailable, .quotaExceeded,
         .notAuthenticated, .networkUnavailable, .networkFailure,
         .accountTemporarilyUnavailable:
        return true
    default:
        return false
    }
}
/// What the relay last took about the saves, so the post is made once per
/// change: nil until it has taken anything.
var relayTookSavesFailing: Bool?
let saveFailuresSaid = 3
/// Cards whose answer the relay has taken, until the relay stops listing
/// them: the tick may still hold a list fetched before the answer, and
/// mirroring one of those again would buzz the wrist a second time.
var answered: Set<String> = []

/// For every relay call: the shared session waits 60 s by default, on a
/// loop that ticks every 2.
let relaySession: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 5
    config.timeoutIntervalForResource = 10
    return URLSession(configuration: config)
}()

/// Local time with its offset, so a line in bridge.log can be set beside
/// the relay's log and a crash report without guessing when it was written.
let logClock: ISO8601DateFormatter = {
    let clock = ISO8601DateFormatter()
    clock.timeZone = .current
    return clock
}()

func log(_ message: String) {
    let line = "\(logClock.string(from: Date())) bridge: \(message)\n"
    FileHandle.standardError.write(Data(line.utf8))
}

/// The relay's pending cards, or nil when the relay could not say.
///
/// Nil, not []: an empty list means "retract every mirrored card", and a
/// relay that is merely restarting must not wipe the cards off every away
/// watch for the two seconds it takes to come back.
@MainActor func fetchPending() async -> [Card]? {
    // source=bridge keeps these polls out of the relay's "watch seen"
    // diagnostics — only a real watch should count as a watch.
    guard let url = URL(string: relayBase.absoluteString + "/pending?source=bridge")
    else { return nil }
    guard let (data, response) = try? await relayData(for: URLRequest(url: url)),
        (response as? HTTPURLResponse)?.statusCode == 200,
        let pending = try? JSONDecoder().decode(Pending.self, from: data)
    else { return nil }
    return pending.cards
}

// The tick and the answers' loop share `mirrored` and `answered`; each
// function that touches them runs on the main actor, so the two loops take
// turns at every await instead of racing.
@MainActor func mirror(_ card: Card) async {
    let record = CKRecord(recordType: "Card",
                          recordID: CKRecord.ID(recordName: card.id))
    record["tier"] = card.tier
    record["headline"] = card.headline
    record["detail"] = encryptedOnly ? nil : card.detail
    record["project"] = card.project
    record["kind"] = card.kind
    record["options"] = card.options
    record["alert"] = card.alertBucket
    // New fields need to be in the CloudKit Production schema before this
    // bridge is installed: Production refuses a record with a field it does
    // not know (RELEASING.md, "The Mac bridge"). CloudKit has no list of
    // lists, so the facts travel as JSON text.
    let facts = card.facts.flatMap {
        (try? JSONEncoder().encode($0)).flatMap { String(data: $0, encoding: .utf8) } }
    record["plan"] = encryptedOnly ? nil : card.plan
    record["facts"] = encryptedOnly ? nil : facts
    // What is being done also travels encrypted (#645 S12): CloudKit seals
    // `encryptedValues` with a key in the user's iCloud Keychain, so Apple
    // cannot read it even without Advanced Data Protection. A field is plain
    // or encrypted for life, hence the new names. The plain copies above go
    // once this computer's watch reads these (`encryptedOnly`, #820);
    // headline and tier stay plain for good: the alert is built from them.
    record.encryptedValues["encDetail"] = card.detail
    record.encryptedValues["encPlan"] = card.plan
    record.encryptedValues["encFacts"] = facts
    record["sessionId"] = card.sessionID
    record["canAlways"] = card.canAlways.map { ($0 ? 1 : 0) as Int64 }
    record["sessionTitle"] = card.sessionTitle
    record["planMarked"] = card.planMarked
    record["allowLabel"] = card.allowLabel
    record["denyLabel"] = card.denyLabel
    record["agent"] = card.agent
    record["multiSelect"] = card.multiSelect.map { ($0 ? 1 : 0) as Int64 }
    record["questionHeader"] = card.questionHeader
    record["optionDetails"] = card.optionDetails
    record["marker"] = 1 as Int64
    do {
        _ = try await cloud { try await $0.save(record) }
        mirrored.insert(card.id)
        savesWorked()
        // T1 of the buzz-when-closed latency measurement, next to the
        // relay's "queued <id> ... at <ms>" (T0).
        log("mirrored \(card.id) \(card.alertBucket) at "
            + "\(Int(Date().timeIntervalSince1970 * 1000)) \(card.tier) \(card.headline)")
    } catch let error as CKError where error.code == .serverRecordChanged {
        mirrored.insert(card.id)
        savesWorked()
    } catch {
        saveFailures += 1
        lastSaveError = error.localizedDescription
        let wait = (error as? CKError)?.retryAfterSeconds ?? 30
        if holdsEverySave(error) {
            savesHeldUntil = Date().addingTimeInterval(wait)
            log("mirror failed (\(saveFailures) in a row, next try in \(Int(wait)) s): \(lastSaveError)")
        } else {
            cardHeldUntil[card.id] = Date().addingTimeInterval(wait)
            log("mirror of \(card.id) refused (\(saveFailures) in a row, that card again in "
                + "\(Int(wait)) s, the others now): \(lastSaveError)")
        }
    }
}

/// A save went through: the run of refusals is over.
@MainActor func savesWorked() {
    saveFailures = 0
    lastSaveError = ""
    savesHeldUntil = .distantPast
}

/// Tell the relay when the saves have been refused `saveFailuresSaid` times
/// in a row, and again when they work, once per change. No answer is a
/// relay restarting; the next tick asks again.
@MainActor func reportSaves() async {
    let failing = saveFailures >= saveFailuresSaid
    if relayTookSavesFailing == failing { return }
    var saves: [String: Any] = ["failing": failing]
    if failing { saves["error"] = lastSaveError }
    guard let status = await postJSON("bridge-status", ["saves": saves]) else { return }
    if (200..<300).contains(status) { relayTookSavesFailing = failing }
}

@MainActor func unmirror(_ id: String) async {
    _ = try? await cloud { try await $0.deleteRecord(withID: CKRecord.ID(recordName: id)) }
    mirrored.remove(id)
}

func relayRequest(_ path: String) -> URLRequest {
    URLRequest(url: relayBase.appendingPathComponent(path))
}

// MARK: - Proven relay answers
//
// Kept to Foundation and RelaySigning: the suite compiles this region alone
// and runs it against a relay that proves itself and several that do not.

enum RelayRefusal: Error {
    case noKey
    case unproven(path: String, status: Int)
}

/// `request`, signed v2 with `key` and sent; its answer only if it carries
/// the relay's proof2 over this nonce, its status and its body.
///
/// Signing alone proved the bridge to the relay and nothing the other way:
/// whatever held port 8977 could hand the bridge cards to mirror and a
/// /tunnel address to put in iCloud for every away watch to adopt
/// (2026-10-16 review, S10). Only the relay holding the key can make this
/// proof, and an answer without it is no answer.
func provenData(for request: URLRequest, key: String?,
                session: URLSession) async throws -> (Data, HTTPURLResponse) {
    guard let key, !key.isEmpty else { throw RelayRefusal.noKey }
    var signed = request
    let nonce = RelaySigning.nonce()
    signed.setValue(RelaySigning.header(key: key, request: request, nonce: nonce,
                                        stamp: Int(Date().timeIntervalSince1970), v2: true),
                    forHTTPHeaderField: "X-Tapproval-Signature")
    let (data, response) = try await session.data(for: signed)
    let http = response as? HTTPURLResponse
    let status = http?.statusCode ?? 0
    guard let http, let proof = http.value(forHTTPHeaderField: "X-Tapproval-Proof2"),
          proof == RelaySigning.proof2(key: key, nonce: nonce, status: status, body: data)
    else { throw RelayRefusal.unproven(path: request.url?.path ?? "?", status: status) }
    return (data, http)
}

// MARK: - End of proven relay answers

var refusalsSaid: Set<String> = []

/// Each kind of refusal once in bridge.log: a relay too old for a route
/// answers it unproven on every look, and a squatter on every tick.
@MainActor func sayOnce(_ refusal: RelayRefusal) {
    let line: String
    switch refusal {
    case .noKey:
        line = "no key in ~/.tapproval/data/auth.json or ~/.tapproval-auth.json; the relay cannot be asked"
    case let .unproven(path, status):
        line = "an answer from \(path) (HTTP \(status)) without the relay's proof; ignored"
    }
    if refusalsSaid.insert(line).inserted { log(line) }
}

/// Every relay call goes through here, signed with the bootstrap key at the
/// last moment — after the body is set, because the signature covers it —
/// and believed only when the answer proves the same key.
///
/// Loopback reads need no key, but /decision does: a command Claude runs
/// is a local process too, and must not answer its own card. This used to
/// send the key itself in X-Tapproval-Token, which kept the relay
/// accepting a key sent in the clear from every caller.
@MainActor func relayData(for request: URLRequest) async throws -> (Data, URLResponse) {
    do {
        return try await provenData(for: request, key: bootstrapToken(), session: relaySession)
    } catch let refusal as RelayRefusal {
        sayOnce(refusal)
        throw refusal
    }
}

/// The HTTP status the relay answered with, or nil when it did not answer.
@discardableResult
func postJSON(_ path: String, _ body: [String: Any]) async -> Int? {
    var request = relayRequest(path)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    guard let (_, response) = try? await relayData(for: request)
    else { return nil }
    return (response as? HTTPURLResponse)?.statusCode
}

/// Did the relay take the answer — or refuse it for good? Either way the
/// Decision record has done its job. False only when trying again later
/// could change the outcome: no reply at all, a relay still starting, a
/// key it does not know yet, a rate limit.
///
/// The watch has already said "Sent via iCloud". Deleting the record on a
/// failed post lost that answer with nothing anywhere saying so, and the
/// prompt fell back to the terminal — CloudRelay.swift calls exactly that
/// the worst failure this app has.
func postDecision(cardID: String, verdict: String, answer: String?) async -> Bool {
    var body: [String: Any] = ["id": cardID, "decision": verdict]
    if let answer { body["answer"] = answer }
    guard let status = await postJSON("decision", body) else { return false }
    if status == 403 || status == 429 || status >= 500 { return false }
    return true
}

@MainActor func drainDecisions() async {
    let query = CKQuery(recordType: "Decision",
                        predicate: NSPredicate(format: "marker == 1"))
    guard let (results, _) = try? await cloud({
        try await $0.records(matching: query, resultsLimit: 20) }) else { return }
    for (recordID, result) in results {
        guard let record = try? result.get(),
              let cardID = record["cardId"] as? String,
              let verdict = record["verdict"] as? String else { continue }
        log("decision from watch: \(verdict) for \(cardID)")
        guard await postDecision(cardID: cardID, verdict: verdict,
                                 answer: record["answer"] as? String) else {
            log("relay did not take the decision for \(cardID); keeping it for the next look")
            continue
        }
        answered.insert(cardID)
        _ = try? await cloud { try await $0.deleteRecord(withID: recordID) }
        await unmirror(cardID)
    }
}

// MARK: - Address book: the watch finds its way home through iCloud
//
// The tunnel URL changes when the computer restarts (and, with a helper
// older than 1.1.27, on every relay restart); a watch that left the house
// with the old one is stranded. Mirroring the current addresses
// (and the pairing token) into a well-known record lets an away watch
// re-learn them without ever being on the home Wi-Fi.

/// The certificate the relay's encrypted listener answers with, from
/// /tunnel's "tls" (helper with #645 S4): an away watch learns it here for
/// the tailnet address, which it may never have asked at home.
struct TLSPin: Codable, Equatable { let port: Int; let sha256: String }

struct Tunnel: Codable {
    let url: String?; let tailscale: String?; let tls: TLSPin?
    /// 1 once this computer's watch has shown it runs 2.1 or newer (#820).
    let updatedWatch: Int?
    enum CodingKeys: String, CodingKey {
        case url, tailscale, tls
        case updatedWatch = "updated_watch"
    }
}

/// Whether to stop writing the readable iCloud copies of a card's details
/// and the pairing key (#820): only once the relay has seen this computer's
/// watch run 2.1 or newer, which reads the encrypted ones. Until then, and
/// with a helper that does not say, a watch on 2.0 keeps its details.
var encryptedOnly = false

var lastMirroredInfo: [String?] = []

/// The bootstrap key, read straight from the relay's own 0600 auth file.
///
/// This used to be fetched from `GET /pair`, which meant that endpoint had
/// to answer local callers — and on the tunnel listener a local caller is
/// cloudflared, so the whole internet could ask for the key. Reading the
/// file removes /pair's last legitimate caller, and it keeps working while
/// the relay is restarting, where the old fetch would mirror a nil token
/// and strand an away watch.
///
/// The key lives in ~/.tapproval/data/ since 1.0.1. The helper moves it
/// there from ~/.tapproval-auth.json only once a bridge that reads the new
/// place is installed, so the old place is still read for a helper that
/// has not moved it yet.
let authFiles = ["~/.tapproval/data/auth.json", "~/.tapproval-auth.json"]

func bootstrapToken() -> String? {
    for name in authFiles {
        let path = (name as NSString).expandingTildeInPath
        guard let data = FileManager.default.contents(atPath: path) else {
            continue
        }
        guard let root = try? JSONSerialization.jsonObject(with: data)
                  as? [String: Any],
              root["version"] as? Int == 1
        else { return nil }
        return root["bootstrap"] as? String
    }
    return nil
}

@MainActor func mirrorRelayInfo() async {
    guard let (tunnelData, _) = try? await relayData(
        for: relayRequest("tunnel")),
        let tunnel = try? JSONDecoder().decode(Tunnel.self, from: tunnelData)
    else { return }
    let token = bootstrapToken()
    // Save only on actual change — the addresses rotate once per relay
    // restart, not per poll, and 288 identical writes a day are pure
    // quota and log noise.
    let pin = tunnel.tls.flatMap {
        (try? JSONEncoder().encode($0)).flatMap { String(data: $0, encoding: .utf8) } }
    encryptedOnly = tunnel.updatedWatch == 1
    let triple = [tunnel.url, tunnel.tailscale, token, pin, encryptedOnly ? "sealed" : "both"]
    if triple == lastMirroredInfo { return }
    let id = CKRecord.ID(recordName: "relay-info")
    let record = (try? await cloud { try await $0.record(for: id) })
        ?? CKRecord(recordType: "RelayInfo", recordID: id)
    record["url"] = tunnel.url
    record["tailscale"] = tunnel.tailscale
    // Sealed as the card's detail is (#645 S12). The plain copy goes with
    // the card's (#820); nil also clears the one an earlier save left.
    record["token"] = encryptedOnly ? nil : token
    record.encryptedValues["encToken"] = token
    // Encrypted only: no watch before this one reads a pin from iCloud.
    record.encryptedValues["encTls"] = pin
    do {
        _ = try await cloud { try await $0.save(record) }
        lastMirroredInfo = triple
        // The host only: the path after it is the tunnel's secret, and this
        // log is a plain file (2026-09-30 review).
        let host = tunnel.url.flatMap { URL(string: $0)?.host } ?? "none"
        log("relay-info mirrored (tunnel: \(host))")
    } catch {
        log("relay-info mirror failed: \(error.localizedDescription)")
    }
}

// MARK: - Presence: the watch's cloud heartbeat, reported to the relay
//
// The relay queues cards whether or not a watch is around, but /health
// tells the wrist when one was last seen. An away watch can't poll the
// relay's socket, but it re-saves a heartbeat record while it checks
// iCloud — reading that record's server-side modification date and
// reporting the age keeps that answer honest in both directions.

func relayHeartbeat() async {
    guard let record = try? await cloud({
        try await $0.record(for: CKRecord.ID(recordName: "watch-presence")) }),
        let seen = record.modificationDate else { return }
    let age = Int(Date().timeIntervalSince(seen))
    // Report the raw age (clock skew aside) and let the relay — the one
    // owner of the presence rule — judge freshness; a copied threshold
    // here would silently drift the day the relay's changes.
    guard age >= 0 else { return }
    await postJSON("heartbeat", ["watch_seen_seconds_ago": age])
}

// MARK: - iCloud status, told to the relay
//
// A Mac signed out of iCloud mirrors nothing, and until now only the first
// line of bridge.log said so. The relay turns this into a condition on the
// wrist's Connection screen (route B, #378); a relay older than that route
// answers 404, which changes nothing here.

/// CKAccountStatus as the relay's /bridge-status reads it.
func iCloudName(_ status: CKAccountStatus?) -> String {
    switch status {
    case .available: return "available"
    case .noAccount: return "noAccount"
    case .restricted: return "restricted"
    case .temporarilyUnavailable: return "temporarilyUnavailable"
    case .couldNotDetermine, .none: return "couldNotDetermine"
    @unknown default: return "couldNotDetermine"
    }
}

/// What bridge.log says, for a person reading it.
func iCloudWords(_ name: String) -> String {
    switch name {
    case "noAccount": return "NO ACCOUNT — sign this Mac into iCloud"
    case "temporarilyUnavailable": return "temporarily unavailable"
    case "couldNotDetermine": return "could not determine"
    default: return name
    }
}

var lastSeenICloud: String?
var relayTookICloud: String?
var saidStatusRouteMissing = false

/// Look at the account; tell the relay when what it holds is out of date.
///
/// Sent again until the relay takes it, so a relay that was restarting, or
/// is newer than the bridge's last post, still learns it. A refusal is said
/// once: until the helper carries the route, every post is a 404.
@MainActor func reportICloud() async {
    let name = iCloudName(try? await CKContainer(
        identifier: "iCloud.app.tapproval").accountStatus())
    if let last = lastSeenICloud, last != name {
        log("iCloud account now: \(iCloudWords(name))")
    }
    lastSeenICloud = name
    if relayTookICloud == name { return }
    // No answer at all is a relay restarting: the next look sends it again.
    guard let status = await postJSON("bridge-status", ["icloud": name]) else { return }
    if (200..<300).contains(status) {
        relayTookICloud = name
    } else if !saidStatusRouteMissing {
        saidStatusRouteMissing = true
        log("the relay did not take the iCloud status (HTTP \(status)); "
            + "a helper with /bridge-status will")
    }
}

/// Make iCloud hold exactly the cards the relay is waiting on.
///
/// `mirrored` lives in memory, so a bridge that restarted — a crash, a
/// reboot, a login — forgot every Card record it had written, and none was
/// ever removed: an away watch showed cards that no longer existed, took
/// them as proof a computer was there, and past twenty of them the
/// unsorted query could leave out the live one (2026-09-25 review). Every
/// Card record not pending is deleted; every one that is, is remembered.
@MainActor func reconcileCards(pendingIDs: Set<String>) async {
    let query = CKQuery(recordType: "Card", predicate: NSPredicate(format: "marker == 1"))
    var page = try? await cloud { try await $0.records(matching: query, resultsLimit: 100) }
    while let (results, cursor) = page {
        for (recordID, _) in results {
            if pendingIDs.contains(recordID.recordName) {
                mirrored.insert(recordID.recordName)
            } else {
                _ = try? await cloud { try await $0.deleteRecord(withID: recordID) }
                mirrored.remove(recordID.recordName)
                log("removed a card the relay no longer holds: \(recordID.recordName)")
            }
        }
        guard let cursor else { break }
        page = try? await cloud {
            try await $0.records(continuingMatchFrom: cursor, resultsLimit: 100) }
    }
}

/// The CloudKit environment this copy's signature points at, or nil.
func signedEnvironment() -> String? {
    guard let task = SecTaskCreateFromSelf(nil) else { return nil }
    return SecTaskCopyValueForEntitlement(
        task, "com.apple.developer.icloud-container-environment" as CFString, nil)
        as? String
}

/// Save the specimen card to Production and delete it; true only when
/// Production took every field on it.
///
/// Nobody sees it: marker 0 is outside the watch's query and the bridge's
/// own sweep, and its alert matches none of the watch's subscriptions, so
/// no wrist buzzes while it exists.
func probeProduction(_ card: CKRecord) async -> Bool {
    let environment = signedEnvironment()
    guard environment == "Production" else {
        print("probe: this copy is signed for \(environment ?? "no iCloud environment"), "
            + "not Production; run it on the exported Developer ID app")
        return false
    }
    card["alert"] = "probe-never-matches"
    card["marker"] = 0 as Int64
    let fields = card.allKeys().sorted().joined(separator: ", ")
    do {
        _ = try await cloud { try await $0.save(card) }
        print("probe save: OK — Production takes every field the bridge writes: \(fields)")
    } catch {
        let code = (error as? CKError).map { " [CKError \($0.code.rawValue)]" } ?? ""
        print("probe save: REFUSED\(code): \(error.localizedDescription)")
        print("  fields on the card: \(fields)")
        print("  Deploy Schema Changes to Production before releasing this bridge "
            + "(RELEASING.md, \"The Mac bridge\").")
        return false
    }
    do {
        _ = try await cloud { try await $0.deleteRecord(withID: card.recordID) }
        print("probe delete: OK")
    } catch let error as CKError where error.code == .unknownItem {
        print("probe delete: nothing to delete")
    } catch {
        print("probe delete FAILED, remove Card \(card.recordID.recordName) by hand: "
            + error.localizedDescription)
        return false
    }
    return true
}

var ticks = 0

@MainActor func tick() async {
    if let pending = await fetchPending() {
        let pendingIDs = Set(pending.map(\.id))
        answered.formIntersection(pendingIDs)
        // At start, then once a minute: what an earlier bridge left behind.
        if ticks % 30 == 0 { await reconcileCards(pendingIDs: pendingIDs) }
        // Read afresh for each card: an answer can land at any await here.
        cardHeldUntil = cardHeldUntil.filter { pendingIDs.contains($0.key) }
        for card in pending where !mirrored.contains(card.id) && !answered.contains(card.id) {
            if Date() < savesHeldUntil { break }   // iCloud refused just now: wait it out
            if let until = cardHeldUntil[card.id], Date() < until { continue }   // this one alone
            await mirror(card)
        }
        for stale in mirrored.subtracting(pendingIDs) {
            await unmirror(stale)   // hook gave up; retract the card
        }
        await reportSaves()
    }
    // The watch rewrites its presence record at most every 30s; fetching
    // it every 2s tick would be ~43k CloudKit reads a day for nothing.
    if ticks % 15 == 0 { await relayHeartbeat() }
    ticks += 1
}

// --seed: run once against the DEVELOPMENT environment to JIT-create
// every record type with every field; Bridge/seed-development.sh builds,
// signs and runs it. Production forbids new types; the schema is born here and
// promoted with CloudKit Console's "Deploy Schema Changes" button.
//
// --probe-production: the same specimen Card, saved to the Production
// database and deleted again. release-bridge.sh runs it on the exported app
// before anything is published: Production refuses a whole record with one
// field it does not know, so a bridge released ahead of its schema stops
// every mirrored card without a word (#616 added two). One specimen serves
// both, so the probe can never ask less than the seed registers.
let seeding = CommandLine.arguments.contains("--seed")
let probing = CommandLine.arguments.contains("--probe-production")
if seeding && probing {
    print("--seed writes to Development and --probe-production to Production; pick one")
    exit(2)
}
if seeding || probing {
    var specimens: [CKRecord] = []
    let card = CKRecord(recordType: "Card", recordID: CKRecord.ID(recordName: seeding
        ? "seed-card" : "probe-card-\(Int(Date().timeIntervalSince1970))"))
    card["tier"] = "HIGH"; card["headline"] = "seed"; card["detail"] = "seed"
    card["project"] = "seed"; card["kind"] = "question"
    card["options"] = ["a", "b"]; card["alert"] = "stop"
    card["sessionTitle"] = "seed"
    // Every field mirror() writes, or Production never learns it: the seed
    // missed these four from 2026-09-30, and Production refused canAlways
    // on every card a newer bridge mirrored (2026-10-02).
    card["plan"] = "seed"; card["facts"] = "[]"; card["sessionId"] = "seed"
    card["canAlways"] = 1 as Int64
    card["planMarked"] = "seed"
    card["allowLabel"] = "seed"; card["denyLabel"] = "seed"
    card["agent"] = "seed"
    card["multiSelect"] = 1 as Int64
    card["questionHeader"] = "seed"; card["optionDetails"] = ["a", "b"]
    card.encryptedValues["encDetail"] = "seed"; card.encryptedValues["encPlan"] = "seed"
    card.encryptedValues["encFacts"] = "[]"
    card["marker"] = 1 as Int64
    if probing { exit(await probeProduction(card) ? 0 : 1) }
    specimens.append(card)
    let decision = CKRecord(recordType: "Decision",
                            recordID: CKRecord.ID(recordName: "seed-decision"))
    decision["cardId"] = "seed"; decision["verdict"] = "allow"
    decision["answer"] = "seed"; decision["marker"] = 1 as Int64
    specimens.append(decision)
    let presence = CKRecord(recordType: "Presence",
                            recordID: CKRecord.ID(recordName: "watch-presence"))
    presence["at"] = Date()
    specimens.append(presence)
    // A record of its own: in an account whose bridge already left the
    // real "relay-info", saving one by that name is refused ("record to
    // insert already exists"), and the fields added since never register
    // (encToken, 2026-10-23).
    let info = CKRecord(recordType: "RelayInfo",
                        recordID: CKRecord.ID(recordName: "seed-relay-info"))
    info["url"] = "https://seed.example"; info["tailscale"] = "https://seed"
    info["token"] = "seed"
    info.encryptedValues["encToken"] = "seed"
    info.encryptedValues["encTls"] = #"{"port":1,"sha256":"seed"}"#
    specimens.append(info)
    for record in specimens {
        do {
            _ = try await cloud { try await $0.save(record) }
            log("seeded \(record.recordType)")
        } catch {
            log("seed \(record.recordType) FAILED: \(error.localizedDescription)")
        }
    }
    // The types survive their specimens; leave no seed data behind.
    for name in ["seed-card", "seed-decision", "seed-relay-info"] {
        _ = try? await cloud { try await $0.deleteRecord(withID: CKRecord.ID(recordName: name)) }
    }
    exit(0)
}

// --check-alerts: can this iCloud account's Production database hold the
// watch's alert subscriptions? Lists the ones it has, then saves and deletes
// a probe of exactly their shape — a predicate that can never match, so it
// never fires. Build 144 reported "attempting to create a subscription in a
// production container" once (2026-10-01); a schema never deployed from
// Development refuses every time, a moment's refusal does not, and this
// says which. Run it from a Production-signed copy (RELEASING.md).
if CommandLine.arguments.contains("--check-alerts") {
    var ok = true
    do {
        let ids = Set(try await cloud { try await $0.allSubscriptions() }.map(\.subscriptionID))
        print("subscriptions: \(ids.sorted().joined(separator: ", "))")
        for bucket in ["go", "careful", "stop", "ask"] {
            print("  alerts-\(bucket): \(ids.contains("alerts-\(bucket)") ? "present" : "MISSING")")
        }
    } catch {
        ok = false
        print("listing subscriptions FAILED: \(error.localizedDescription)")
    }
    let probeID = "probe-alerts-\(Int(Date().timeIntervalSince1970))"
    let probe = CKQuerySubscription(
        recordType: "Card",
        predicate: NSPredicate(format: "alert == %@", "probe-never-matches"),
        subscriptionID: probeID, options: [.firesOnRecordCreation])
    let info = CKSubscription.NotificationInfo()   // as the watch's Alerts.swift
    info.titleLocalizationKey = "%1$@"
    info.titleLocalizationArgs = ["tier"]
    info.alertLocalizationKey = "%1$@"
    info.alertLocalizationArgs = ["headline"]
    info.category = "careful"
    info.soundName = "default"
    probe.notificationInfo = info
    do {
        _ = try await cloud { try await $0.save(probe) }
        print("probe save: OK — this environment can create the alert subscription")
    } catch {
        ok = false
        let code = (error as? CKError).map { " [CKError \($0.code.rawValue)]" } ?? ""
        print("probe save: REFUSED\(code): \(error.localizedDescription)")
    }
    do {
        _ = try await cloud { try await $0.deleteSubscription(withID: probeID) }
        print("probe delete: OK")
    } catch let error as CKError where error.code == .unknownItem {
        print("probe delete: nothing to delete")
    } catch {
        ok = false
        print("probe delete FAILED, remove \(probeID) by hand: \(error.localizedDescription)")
    }
    exit(ok ? 0 : 1)
}

// --agent: started by the login item. Its job file is sealed in the app and
// cannot name a home folder, so the bridge sends its own output to
// bridge.log beside the app, where the helper's job file used to send it.
if CommandLine.arguments.contains("--agent") {
    let logPath = Bundle.main.bundleURL.deletingLastPathComponent()
        .appendingPathComponent("bridge.log").path
    let fd = open(logPath, O_WRONLY | O_APPEND | O_CREAT, 0o644)
    if fd >= 0 {
        dup2(fd, STDOUT_FILENO)
        dup2(fd, STDERR_FILENO)
        close(fd)
    }
    wakeRelay()
}

/// Wake the relay at login, in place of the relay's own job file (which
/// Login Items listed under the interpreter's name). The helper writes
/// which Python and which watch_relay.py; the bridge runs exactly that with
/// --ensure, once, and does not wait: --ensure starts the relay in a
/// session of its own and returns at once if it is already up.
func wakeRelay() {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let file = home + "/.tapproval/data/relay-start.json"
    guard let data = FileManager.default.contents(atPath: file) else { return }
    guard let start = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let python = start["python"] as? String,
          let relay = start["relay"] as? String else {
        log("relay-start.json unreadable; the relay starts with the next Claude Code session")
        return
    }
    // Only the helper's own relay, run by a real interpreter: this file
    // can make the bridge start a program, so it starts nothing else.
    // The two places the helper lives: a terminal install, a plugin install
    // (bridge_install.RELAY_HOMES says the same).
    let real = URL(fileURLWithPath: relay).resolvingSymlinksInPath().path
    guard [home + "/.tapproval/", home + "/.claude/plugins/"].contains(where: real.hasPrefix),
          (real as NSString).lastPathComponent == "watch_relay.py",
          FileManager.default.fileExists(atPath: real),
          python.hasPrefix("/"),
          FileManager.default.isExecutableFile(atPath: python) else {
        log("relay-start.json names something other than the helper's relay; not started")
        return
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: python)
    process.arguments = [real, "--ensure"]
    do {
        try process.run()
        log("woke the relay")
    } catch {
        log("could not wake the relay: \(error.localizedDescription)")
    }
}

let startingICloud = iCloudName(try? await CKContainer(
    identifier: "iCloud.app.tapproval").accountStatus())
lastSeenICloud = startingICloud
log("starting — iCloud account: \(iCloudWords(startingICloud))")

// Answers have a loop of their own: inside the tick they waited behind
// every iCloud save, so a wrist's answer could sit there for a minute
// (2026-10-16 review, L4). Every second while anything is mirrored — a
// decision exists only for a mirrored card — and otherwise every 30 s, which
// still collects one left from before a restart.
Task { @MainActor in
    var seconds = 0
    while true {
        if !mirrored.isEmpty || seconds % 30 == 0 { await drainDecisions() }
        seconds += 1
        try? await Task.sleep(nanoseconds: 1_000_000_000)
    }
}

while true {
    if ticks % 150 == 0 {   // every ~5 min, and at startup
        await mirrorRelayInfo()
        relayTookICloud = nil   // a relay that restarted has forgotten it
        relayTookSavesFailing = nil
    }
    // Every 30 s: a change of account reaches the wrist within that.
    if ticks % 15 == 0 { await reportICloud() }
    await tick()            // increments ticks
    try? await Task.sleep(nanoseconds: 2_000_000_000)
}
