#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "types/ipaddress.h"
#include "../common/dns_filter_ownership.h"

// Which program-scoped firewall rules to install, and how the DNS leak filter's rules are replaced,
// kept free of WFP so it can be unit-tested.
namespace scoped_permits {

// FirewallFilter: the "Windscribe programs only" address permits to add. None when Windscribe's
// programs could not be identified: a permit without a program condition applies to every program,
// so falling back to one would reopen exactly the access these permits restrict. The firewall stays
// on without them and the caller reports the failure.
inline std::vector<std::wstring> windscribeOnlyPermits(const std::vector<std::wstring> &ips, size_t knownAppsCount)
{
    if (knownAppsCount == 0) {
        return {};
    }
    return ips;
}

// Where a resolver of a local network (a router) can live: private IPv4, link-local, IPv6 ULA and
// link-local.
inline std::vector<types::IpAddressRange> localNetworkRanges()
{
    return {types::IpAddressRange(std::string("10.0.0.0/8")),   types::IpAddressRange(std::string("172.16.0.0/12")),
            types::IpAddressRange(std::string("192.168.0.0/16")), types::IpAddressRange(std::string("169.254.0.0/16")),
            types::IpAddressRange(std::string("fc00::/7")),     types::IpAddressRange(std::string("fe80::/10"))};
}

inline bool rangeContains(const types::IpAddressRange &range, const types::IpAddress &addr)
{
    if (!range.isValid() || !addr.isValid() || range.family() != addr.family()) {
        return false;
    }
    const uint8_t *a = range.address().bytes();
    const uint8_t *b = addr.bytes();
    size_t bits = range.prefixLength();
    for (size_t i = 0; bits > 0; ++i) {
        const size_t take = bits >= 8 ? 8 : bits;
        const uint8_t mask = static_cast<uint8_t>(0xFF << (8 - take));
        if ((a[i] & mask) != (b[i] & mask)) {
            return false;
        }
        bits -= take;
    }
    return true;
}

struct DnsRule
{
    types::IpAddressRange target;
    bool isPermitForApps;  // false: block port 53 for every program; true: permit the listed programs
};

// DnsFirewall rules (port 53, UDP and TCP).
// Connected (permitApps false): a block for each adapter DNS server except the excluded ones (the
// custom connected DNS / ctrld upstreams the user chose), as upstream.
// Not connected under a proxy (permitApps true): blocks for every local-network range, so a router
// reached after a network change is covered before anyone has seen its address, plus each adapter DNS
// server outside them. Exclusions do not apply: the custom connected DNS is not in use then, and ctrld
// is among the permitted programs. Each block gets a permit for the permitted programs (Windscribe's
// own and Exclusive-mode excluded apps) when there are any.
inline std::vector<DnsRule> dnsFilterRules(const std::set<types::IpAddress> &servers,
                                           const std::set<types::IpAddress> &excluded, bool permitApps,
                                           size_t permittedAppsCount)
{
    std::vector<types::IpAddressRange> targets;
    if (permitApps) {
        targets = localNetworkRanges();
    }
    for (const auto &server : servers) {
        if (!permitApps && excluded.count(server) > 0) {
            continue;
        }
        bool isCovered = false;
        for (const auto &range : targets) {
            if (range.prefixLength() < (server.isV4() ? 32 : 128) && rangeContains(range, server)) {
                isCovered = true;
                break;
            }
        }
        if (!isCovered) {
            targets.push_back(types::IpAddressRange(server, server.isV4() ? 32 : 128));
        }
    }

    std::vector<DnsRule> rules;
    for (const auto &target : targets) {
        rules.push_back(DnsRule{target, false});
        if (permitApps && permittedAppsCount > 0) {
            rules.push_back(DnsRule{target, true});
        }
    }
    return rules;
}

// The DNS baseline: whenever the main firewall is on (connected, reconnecting, disconnected with
// Always On, and from when Windows loads persistent filters at boot), port 53 (UDP and TCP) is
// blocked for every program, on every interface and to every address. The firewall's LAN permit
// (Allow LAN, and always for imported profiles) would otherwise let any program query a router
// directly, also one no adapter lists any more (e.g. after switching the Wi-Fi's DNS to a public
// one). Being on every interface, it covers adapters it has never seen (one plugged in while
// Windows was off, or later) without having to know about them. Permitted:
// - Windscribe's programs and Exclusive-mode excluded apps (Throne), everywhere;
// - every program over Windscribe's own tunnel adapters (DNS through the VPN) and to loopback
//   (local DNS such as ctrld);
// - every program to the custom connected DNS addresses, while connected (they may be on the LAN).
// Only what holds whatever adapters exist is persistent (the block, the programs' permit, loopback):
// tunnel and custom-DNS permits are not, so a reboot never brings back a stale exception.
enum class BaselineAction {
    kBlock,           // port 53, every program
    kPermitApps,      // Windscribe's programs and excluded apps
    kPermitLoopback,  // every program, to loopback
    kPermitTunnel,    // every program, over a Windscribe tunnel adapter
    kPermitAddress    // every program, to a custom connected DNS address
};

struct BaselineRule
{
    BaselineAction action;
    bool isV6;
    uint64_t interfaceLuid;       // kPermitTunnel only; 0 = every interface
    types::IpAddressRange range;  // kPermitLoopback / kPermitAddress only
    bool isPersistent;
};

inline bool isBlockRule(const BaselineRule &rule)
{
    return rule.action == BaselineAction::kBlock;
}

// WFP weight within the baseline's sublayer: the highest matching filter decides.
inline uint8_t baselineWeight(BaselineAction action)
{
    switch (action) {
    case BaselineAction::kBlock:
        return 6;
    case BaselineAction::kPermitApps:
        return 7;
    case BaselineAction::kPermitLoopback:
    case BaselineAction::kPermitTunnel:
    case BaselineAction::kPermitAddress:
        return 8;
    }
    return 6;
}

inline std::vector<BaselineRule> dnsBaselineRules(const std::set<uint64_t> &tunnelInterfaces,
                                                  const std::set<types::IpAddress> &permittedAddresses,
                                                  size_t permittedAppsCount)
{
    std::vector<BaselineRule> rules;
    for (const bool isV6 : {false, true}) {
        rules.push_back(BaselineRule{BaselineAction::kBlock, isV6, 0, types::IpAddressRange(), true});
        if (permittedAppsCount > 0) {
            rules.push_back(BaselineRule{BaselineAction::kPermitApps, isV6, 0, types::IpAddressRange(), true});
        }
        rules.push_back(BaselineRule{BaselineAction::kPermitLoopback, isV6, 0,
                                     types::IpAddressRange(std::string(isV6 ? "::1/128" : "127.0.0.0/8")), true});
        for (const uint64_t luid : tunnelInterfaces) {
            rules.push_back(BaselineRule{BaselineAction::kPermitTunnel, isV6, luid, types::IpAddressRange(), false});
        }
        for (const auto &addr : permittedAddresses) {
            if (addr.isValid() && addr.isV6() == isV6) {
                rules.push_back(BaselineRule{BaselineAction::kPermitAddress, isV6, 0,
                                             types::IpAddressRange(addr, isV6 ? 128 : 32), false});
            }
        }
    }
    return rules;
}

// Whether a program's DNS to addr over the interface gets through the baseline.
inline bool baselineAllows(const std::vector<BaselineRule> &rules, uint64_t interfaceLuid, const types::IpAddress &addr,
                           bool isPermittedProgram)
{
    int best = -1;
    bool isPermit = true;  // nothing matching: the baseline does not stop it
    for (const auto &rule : rules) {
        if (rule.isV6 != addr.isV6()) {
            continue;
        }
        if (rule.interfaceLuid != 0 && rule.interfaceLuid != interfaceLuid) {
            continue;
        }
        if (rule.range.isValid() && !rangeContains(rule.range, addr)) {
            continue;
        }
        if (rule.action == BaselineAction::kPermitApps && !isPermittedProgram) {
            continue;
        }
        const int weight = baselineWeight(rule.action);
        if (weight > best) {
            best = weight;
            isPermit = rule.action != BaselineAction::kBlock;
        }
    }
    return isPermit;
}

// What persists across a reboot.
inline std::vector<BaselineRule> persistentBaselineRules(const std::vector<BaselineRule> &rules)
{
    std::vector<BaselineRule> persistent;
    for (const auto &rule : rules) {
        if (rule.isPersistent) {
            persistent.push_back(rule);
        }
    }
    return persistent;
}

// What the helper finds about an installed filter, to tell whether the baseline's global blocks are
// really there at service start (a sublayer can exist with other rules in it, e.g. an older
// per-adapter version, or none).
struct InstalledFilter
{
    bool isBlock;
    bool isPersistent;
    bool hasRemotePort53;
    bool hasInterfaceCondition;
    bool hasAddressCondition;
    bool hasAppCondition;
};

inline bool isGlobalBaselineBlock(const InstalledFilter &f)
{
    return f.isBlock && f.isPersistent && f.hasRemotePort53 && !f.hasInterfaceCondition && !f.hasAddressCondition &&
           !f.hasAppCondition;
}

// Service start with the firewall kept from before: keep the saved baseline only if both global
// blocks (IPv4 and IPv6) are verified; otherwise build one, and if that fails too, hold the main
// firewall's LAN permit (without the client's request: remove it) until the baseline gets in.
enum class BaselineAtStart { kKeepSaved, kBuild };

inline BaselineAtStart planBaselineAtStart(bool isV4BlockVerified, bool isV6BlockVerified)
{
    return isV4BlockVerified && isV6BlockVerified ? BaselineAtStart::kKeepSaved : BaselineAtStart::kBuild;
}

// The ready callback restores a held LAN permit only if, when it runs, a request is still held, the
// firewall is on and the baseline is in place now: a callback from an earlier activation must not
// restore the LAN permit of a later one whose baseline failed.
inline bool shouldRestoreLanPermit(bool isRequestHeld, bool isFirewallOn, bool isBaselineInPlaceNow)
{
    return isRequestHeld && isFirewallOn && isBaselineInPlaceNow;
}

// The main firewall's own rebuild (FirewallFilter::on): one transaction, committed only with both
// default blocks (IPv4 and IPv6 block-all) added; otherwise aborted, so the rules in place before
// stay. Missing permits (fail closed) commit but count as incomplete.
struct FirewallApplyPlan
{
    bool commit;
    bool isComplete;  // before the commit's own result
};

inline FirewallApplyPlan planFirewallApply(bool hasBegun, bool isV4BlockAdded, bool isV6BlockAdded,
                                           bool areOtherRulesComplete)
{
    if (!hasBegun || !isV4BlockAdded || !isV6BlockAdded) {
        return {false, false};
    }
    return {true, areOtherRulesComplete};
}

// Filter ids the helper records (to remove those filters later, e.g. the split-tunnel permits for an
// excluded app or IP), changed inside a WFP transaction: if it does not commit, Windows keeps the old
// filters, so the old ids must be kept too, or a later removal misses the permit still in force.
template <typename Ids>
class FilterIdsSnapshot
{
public:
    explicit FilterIdsSnapshot(std::vector<Ids *> lists)
        : lists_(std::move(lists))
    {
        for (Ids *list : lists_) {
            saved_.push_back(*list);
        }
    }
    void rollback()
    {
        for (size_t i = 0; i < lists_.size(); ++i) {
            *lists_[i] = saved_[i];
        }
    }

private:
    std::vector<Ids *> lists_;
    std::vector<Ids> saved_;
};

// Deleting filters by their recorded ids, inside a transaction. A filter that is already gone counts
// as deleted; any other failure makes the whole step fail, so the caller aborts the transaction (the
// commit would otherwise go through with that permit still installed) and keeps the recorded ids.
enum class DeleteResult { kDeleted, kNotFound, kFailed };

template <typename Id, typename DeleteById>
inline bool deleteRecordedFilters(const std::vector<Id> &ids, DeleteById deleteById)
{
    bool isEveryOneGone = true;
    for (const Id &id : ids) {
        if (deleteById(id) == DeleteResult::kFailed) {
            isEveryOneGone = false;
        }
    }
    return isEveryOneGone;
}

// Removing a sublayer with all its filters (Utils::deleteSublayerAndAllFilters), inside the caller's
// transaction: only if every filter was listed and deleted (or already gone) and then the sublayer
// itself. WFP commits whatever operations did succeed, so a caller that commits after a partial
// removal would leave some of the rules in force while believing them gone: on false it aborts.
template <typename Id, typename DeleteById, typename DeleteSublayer>
inline bool removeSublayerAndFilters(bool areFiltersListed, const std::vector<Id> &filterIds, DeleteById deleteById,
                                     DeleteSublayer deleteSublayer)
{
    if (!areFiltersListed) {
        return false;  // a filter may have been missed
    }
    if (!deleteRecordedFilters(filterIds, deleteById)) {
        return false;  // the sublayer cannot go while one is left
    }
    return deleteSublayer() != DeleteResult::kFailed;
}

// firewallOn with the DNS baseline: the baseline goes in first. Without it in place the main firewall
// is turned on without its LAN permit (so the LAN DNS path stays closed), the request counts as
// incomplete for the client, and the LAN permit is added once the baseline is in.
struct FirewallOnPlan
{
    bool holdLanPermit;
    bool isComplete;
};

inline FirewallOnPlan planFirewallOn(bool isBaselineInPlace, bool isFirewallComplete)
{
    return {!isBaselineInPlace, isBaselineInPlace && isFirewallComplete};
}

struct DnsRulePlan
{
    bool canApply;    // false: keep the rules in place
    bool isFallback;  // the adapters could not be read; rules from what is known instead
    std::vector<DnsRule> rules;
};

// Rules for the current adapters. If they cannot be read: while not connected under a proxy, the
// local-network ranges plus the last resolvers known are still blocked (so a first enable never ends
// up with no block at all); while connected, the rules in place stay.
inline DnsRulePlan planDnsRules(bool serversKnown, const std::set<types::IpAddress> &servers,
                                const std::set<types::IpAddress> &lastKnownServers,
                                const std::set<types::IpAddress> &excluded, bool permitApps, size_t permittedAppsCount)
{
    if (serversKnown) {
        return {true, false, dnsFilterRules(servers, excluded, permitApps, permittedAppsCount)};
    }
    if (permitApps) {
        return {true, true, dnsFilterRules(lastKnownServers, excluded, true, permittedAppsCount)};
    }
    return {false, false, {}};
}

// The WFP operations replaceDnsRules needs; DnsFirewall implements it with one transaction.
template <typename Rule>
class RuleStore
{
public:
    virtual ~RuleStore() = default;
    virtual bool begin() = 0;
    virtual bool removeAll() = 0;    // every rule of the sublayer, inside the transaction
    virtual bool ensureSublayer() = 0;
    virtual bool add(const Rule &rule) = 0;
    virtual bool commit() = 0;
    virtual void abort() = 0;
};
using DnsRuleStore = RuleStore<DnsRule>;

inline bool isBlockRule(const DnsRule &rule)
{
    return !rule.isPermitForApps;
}

enum class ReplaceResult {
    kApplied,
    kAppliedWithoutSomePermits,  // every block is in; a permit is missing (fails closed), retry
    kKeptPrevious                // nothing changed: the rules in place before stay in place
};

// Replaces the rules in one transaction. The old rules are removed only if every new block can be
// added and the transaction commits; otherwise it is aborted and the old rules stay. canApply is
// false when there is nothing reliable to apply (see planDnsRules).
template <typename Rule>
inline ReplaceResult replaceDnsRules(RuleStore<Rule> &store, bool canApply, const std::vector<Rule> &rules)
{
    if (!canApply || !store.begin()) {
        return ReplaceResult::kKeptPrevious;
    }
    if (!store.removeAll() || !store.ensureSublayer()) {
        store.abort();
        return ReplaceResult::kKeptPrevious;
    }
    bool isEveryPermitAdded = true;
    for (const auto &rule : rules) {
        if (!store.add(rule)) {
            if (isBlockRule(rule)) {
                store.abort();
                return ReplaceResult::kKeptPrevious;
            }
            isEveryPermitAdded = false;
        }
    }
    if (!store.commit()) {
        store.abort();
        return ReplaceResult::kKeptPrevious;
    }
    return isEveryPermitAdded ? ReplaceResult::kApplied : ReplaceResult::kAppliedWithoutSomePermits;
}

// Whether the filter must be rebuilt for the adapters' current DNS servers: a resolver can change
// without the network changing (DHCP renewal, a manual DNS change on the same Wi-Fi), so the helper
// compares the list itself. Nothing to do when the adapters could not be read.
inline bool dnsServersChanged(bool serversKnown, const std::set<types::IpAddress> &current,
                              const std::set<types::IpAddress> &applied)
{
    return serversKnown && current != applied;
}

// The programs the filter's permits are meant for, against those of the rules actually in place. A
// failed rebuild keeps the old rules, old permits included, so a request for the same list again
// still needs a rebuild until one succeeds.
template <typename Apps>
class PermittedAppsTracker
{
public:
    // Returns true when the rules in place do not match the requested programs.
    bool request(const Apps &apps)
    {
        requested_ = apps;
        return needsRebuild();
    }
    bool needsRebuild() const { return !isApplied_ || !(requested_ == applied_); }
    // Rules for the requested programs were committed.
    void onApplied()
    {
        applied_ = requested_;
        isApplied_ = true;
    }
    // Rules without permits (or none) are in place; any program list differs from them.
    void onNoPermitsInPlace() { isApplied_ = false; }
    const Apps &requested() const { return requested_; }

private:
    Apps requested_ {};
    Apps applied_ {};
    bool isApplied_ = false;
};

// What the DNS leak filter's owner asked for. A request is checked against the owner first, under the
// caller's lock, and only an accepted one changes anything it carries: a connector's request ignored
// while the engine holds the filter cannot swap the owner's custom DNS exceptions either.
class DnsFilterRequests
{
public:
    bool acceptEnable(DnsLeakFilterOwner requester, bool permitApps, const std::set<types::IpAddress> &excluded)
    {
        if (!ownership_.acceptEnable(requester)) {
            return false;
        }
        isWanted_ = true;
        permitApps_ = permitApps;
        excluded_ = excluded;
        return true;
    }
    bool acceptDisable(DnsLeakFilterOwner requester)
    {
        if (!ownership_.acceptDisable(requester)) {
            return false;
        }
        isWanted_ = false;
        return true;
    }

    bool isWanted() const { return isWanted_; }
    bool permitApps() const { return permitApps_; }
    const std::set<types::IpAddress> &excluded() const { return excluded_; }
    const DnsLeakFilterOwnership &ownership() const { return ownership_; }

private:
    DnsLeakFilterOwnership ownership_;
    bool isWanted_ = false;
    bool permitApps_ = false;
    std::set<types::IpAddress> excluded_;
};

// The main firewall's state as read from Windows: a failed query is neither on nor off.
enum class FirewallStatus { kOn, kOff, kUnknown };

// Split-tunnel settings: the mode and the excluded (exclusive mode) programs and addresses.
template <class Apps, class Ips>
struct SplitTunnelState {
    bool isEnabled = false;
    bool isExclusive = false;
    Apps apps {};
    Ips ips {};

    // What the firewall's split-tunnel filters are built from: none while disabled; in inclusive mode
    // one permit for every program, so the lists do not matter.
    SplitTunnelState effective() const
    {
        if (!isEnabled) {
            return SplitTunnelState{};
        }
        if (!isExclusive) {
            SplitTunnelState s;
            s.isEnabled = true;
            return s;
        }
        return *this;
    }
    bool operator==(const SplitTunnelState &o) const
    {
        return isEnabled == o.isEnabled && isExclusive == o.isExclusive && apps == o.apps && ips == o.ips;
    }
    bool operator!=(const SplitTunnelState &o) const { return !(*this == o); }
};

enum class SplitTunnelStep {
    kNothing,      // the filters in place match the latest request
    kFirewallOff,  // the firewall is off, so none are in place; its next build uses the request
    kApply,       // rebuild them from the latest request, in one transaction
    kRetryLater   // they differ, but the firewall's state could not be read: still pending
};

// The split-tunnel filters of the main firewall: the latest settings requested (each setter changes
// its part) apart from what Windows has confirmed (the last committed build). Every attempt builds
// from the latest combined request, so a later call (e.g. the mode refresh that follows an app list
// change) carries an earlier change that failed, withdrawing a change that failed leaves nothing to
// retry, and a change made while the firewall's state is unknown stays pending until it can be read.
template <class State>
class SplitTunnelFilterSync
{
public:
    // The request, to change part of it.
    State &request()
    {
        isWaitingForFirewall_ = false;  // a new request: read the firewall's state again
        return requested_;
    }
    const State &requested() const { return requested_; }
    const State &applied() const { return applied_; }

    bool isInSync() const { return !isDirty_ && applied_ == requested_.effective(); }
    // Whether the periodic retry has anything to do.
    bool isPending() const { return !isInSync() && !isWaitingForFirewall_; }

    SplitTunnelStep step(FirewallStatus status)
    {
        if (isInSync()) {
            return SplitTunnelStep::kNothing;
        }
        if (status == FirewallStatus::kOff) {
            // No firewall, no filters; the next firewall build uses the request (onFirewallRebuilt).
            applied_ = State{};
            isDirty_ = false;
            isWaitingForFirewall_ = true;
            return SplitTunnelStep::kFirewallOff;
        }
        return status == FirewallStatus::kOn ? SplitTunnelStep::kApply : SplitTunnelStep::kRetryLater;
    }

    // The rebuild from requested() committed.
    void onApplied()
    {
        applied_ = requested_.effective();
        isDirty_ = false;
    }
    // A rebuild that did not commit leaves Windows (and applied()) as it was: nothing to record.
    void onFailed() {}
    // The whole firewall was rebuilt from requested() and committed; isComplete false when a
    // split-tunnel permit could not be added (rebuilt again by the retry).
    void onFirewallRebuilt(bool isComplete)
    {
        applied_ = requested_.effective();
        isDirty_ = !isComplete;
        isWaitingForFirewall_ = false;
    }
    void onFirewallOff()
    {
        applied_ = State{};
        isDirty_ = false;
        isWaitingForFirewall_ = true;
    }

private:
    State requested_ {};
    State applied_ {};
    bool isDirty_ = false;               // the filters in place are incomplete
    bool isWaitingForFirewall_ = false;  // the firewall is off: nothing to retry until it is rebuilt
};

// The Always On ("firewall on boot") setting as read from the registry. A key or value that is
// missing means never enabled (a fresh install, or turned off: disabling deletes the value); one that
// exists but cannot be read is neither.
enum class RegistryRead { kOk, kNotFound, kFailed };
enum class BootSetting { kEnabled, kDisabled, kUnreadable };

inline BootSetting bootSettingFromRegistry(RegistryRead key, RegistryRead value, uint32_t data)
{
    if (key == RegistryRead::kFailed) {
        return BootSetting::kUnreadable;
    }
    if (key == RegistryRead::kNotFound) {
        return BootSetting::kDisabled;
    }
    if (value == RegistryRead::kFailed) {
        return BootSetting::kUnreadable;
    }
    if (value == RegistryRead::kNotFound) {
        return BootSetting::kDisabled;
    }
    return data == 1 ? BootSetting::kEnabled : BootSetting::kDisabled;
}

// The client's setFirewallOnBoot: the latest value asked for stays pending until written, retried
// periodically (a reboot meanwhile would otherwise follow the old value), and the client is told.
class BootSettingWrites
{
public:
    void request(bool isEnabled)
    {
        wanted_ = isEnabled;
        isPending_ = true;
    }
    // The value to write now, if any.
    std::optional<bool> next() const { return isPending_ ? std::optional<bool>(wanted_) : std::nullopt; }
    void onWritten(bool isEnabled, bool isWritten)
    {
        if (isWritten && isEnabled == wanted_) {
            isPending_ = false;
        }
    }
    bool isPending() const { return isPending_; }

private:
    bool wanted_ = false;
    bool isPending_ = false;
};

// The helper's main firewall work that waits for a retry (process_command.cpp). The DNS baseline
// goes only once the main firewall is known to be off: with the firewall (and its LAN permit) still
// in force, removing it would let any program reach a router's DNS.
//  - Service start while the Always On setting or the firewall's state cannot be read: nothing is
//    touched (the saved firewall and DNS baseline stay) until both can be.
//  - A removal of the main firewall that failed (firewallOff, or service start with Always On
//    disabled): the firewall and the baseline stay, and the removal is retried.
// A firewallOn or firewallOff from the client decides afresh.
class PendingFirewallWork
{
public:
    enum class Action {
        kNone,            // nothing now (keep what is installed)
        kTurnOff,         // remove the main firewall, then report it with onTurnedOff()
        kAdoptBaseline,   // the firewall kept from before: keep (or build) its DNS baseline
        kRemoveBaseline   // the main firewall is off: the DNS baseline goes too
    };

    // Service start (and its retries): the Always On setting and the firewall's state, each of which
    // may be unreadable; then nothing is touched (the saved firewall and DNS baseline stay).
    Action atStart(BootSetting setting, FirewallStatus status)
    {
        if (setting == BootSetting::kUnreadable) {
            isDecisionPending_ = true;
            return Action::kNone;
        }
        if (setting == BootSetting::kDisabled) {
            return requestTurnOff();
        }
        return decide(status);
    }
    // The client's firewallOff.
    Action requestTurnOff()
    {
        isDecisionPending_ = false;
        isTurnOffPending_ = true;
        return Action::kTurnOff;
    }
    // The result of a kTurnOff: the baseline goes only with the main firewall.
    Action onTurnedOff(bool isOff)
    {
        if (!isOff) {
            return Action::kNone;  // retried
        }
        isTurnOffPending_ = false;
        return Action::kRemoveBaseline;
    }
    // The client's firewallOn: it rebuilds everything.
    void onFirewallOn()
    {
        isDecisionPending_ = false;
        isTurnOffPending_ = false;
    }
    // The periodic retry, with the setting and the firewall's state read now.
    Action retry(BootSetting setting, FirewallStatus status)
    {
        if (isTurnOffPending_) {
            return Action::kTurnOff;
        }
        if (isDecisionPending_) {
            return atStart(setting, status);
        }
        return Action::kNone;
    }
    bool isPending() const { return isTurnOffPending_ || isDecisionPending_; }

private:
    Action decide(FirewallStatus status)
    {
        isDecisionPending_ = status == FirewallStatus::kUnknown;
        switch (status) {
        case FirewallStatus::kOn:
            return Action::kAdoptBaseline;
        case FirewallStatus::kOff:
            return Action::kRemoveBaseline;
        default:
            return Action::kNone;
        }
    }

    bool isDecisionPending_ = false;
    bool isTurnOffPending_ = false;
};

// Ipv6Firewall: its last request (block IPv6 outside the tunnel, or lift the block), retried while it
// has not been committed. A failed attempt is aborted, so the rules in place stay as they were; a
// newer request replaces it.
class Ipv6FirewallRequests
{
public:
    enum class Request { kNone, kBlock, kUnblock };
    void onAttempt(Request request, bool isCommitted) { pending_ = isCommitted ? Request::kNone : request; }
    Request pending() const { return pending_; }

private:
    Request pending_ = Request::kNone;
};

} // namespace scoped_permits
