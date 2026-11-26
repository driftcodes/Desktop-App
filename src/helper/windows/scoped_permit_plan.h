#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
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
// Always On, and from boot, being persistent like the firewall's rules), port 53 over the physical
// adapters is blocked for every program and every address, listed as a DNS server or not. The
// firewall's LAN permit (Allow LAN, and always for imported profiles) would otherwise let any
// program query a router directly, also one no adapter lists any more (e.g. after switching the
// Wi-Fi's DNS to a public one). Scoped to the physical adapters, it leaves DNS through the VPN
// adapter alone. Windscribe's programs and Exclusive-mode excluded apps are permitted; while
// connected, so are the custom connected DNS addresses (they may be on the LAN).
enum class BaselineAction {
    kBlock,          // port 53 on this adapter, every program, every address
    kPermitApps,     // the same for Windscribe's programs and excluded apps
    kPermitAddress   // port 53 to this address on this adapter, every program
};

struct BaselineRule
{
    uint64_t interfaceLuid;
    bool isV6;
    BaselineAction action;
    types::IpAddress address;  // kPermitAddress only
};

inline bool isBlockRule(const BaselineRule &rule)
{
    return rule.action == BaselineAction::kBlock;
}

inline std::vector<BaselineRule> dnsBaselineRules(const std::set<uint64_t> &physicalInterfaces,
                                                  const std::set<types::IpAddress> &permittedAddresses,
                                                  size_t permittedAppsCount)
{
    std::vector<BaselineRule> rules;
    for (const uint64_t luid : physicalInterfaces) {
        for (const bool isV6 : {false, true}) {
            rules.push_back(BaselineRule{luid, isV6, BaselineAction::kBlock, types::IpAddress()});
            if (permittedAppsCount > 0) {
                rules.push_back(BaselineRule{luid, isV6, BaselineAction::kPermitApps, types::IpAddress()});
            }
            for (const auto &addr : permittedAddresses) {
                if (addr.isValid() && addr.isV6() == isV6) {
                    rules.push_back(BaselineRule{luid, isV6, BaselineAction::kPermitAddress, addr});
                }
            }
        }
    }
    return rules;
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

} // namespace scoped_permits
