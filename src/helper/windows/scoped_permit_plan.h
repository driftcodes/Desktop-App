#pragma once

#include <array>
#include <cstddef>
#include <set>
#include <string>
#include <vector>

#include "types/ipaddress.h"

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

// The WFP operations replaceDnsRules needs; DnsFirewall implements it with one transaction.
class DnsRuleStore
{
public:
    virtual ~DnsRuleStore() = default;
    virtual bool begin() = 0;
    virtual bool removeAll() = 0;    // every rule of the sublayer, inside the transaction
    virtual bool ensureSublayer() = 0;
    virtual bool add(const DnsRule &rule) = 0;
    virtual bool commit() = 0;
    virtual void abort() = 0;
};

enum class ReplaceResult {
    kApplied,
    kAppliedWithoutSomePermits,  // every block is in; a permit is missing (fails closed), retry
    kKeptPrevious                // nothing changed: the rules in place before stay in place
};

// Replaces the rules in one transaction. The old rules are removed only if every new block can be
// added and the transaction commits; otherwise it is aborted and the old rules stay. serversKnown is
// false when the adapters' DNS servers could not be read (an error, unlike a network with none).
inline ReplaceResult replaceDnsRules(DnsRuleStore &store, bool serversKnown, const std::vector<DnsRule> &rules)
{
    if (!serversKnown || !store.begin()) {
        return ReplaceResult::kKeptPrevious;
    }
    if (!store.removeAll() || !store.ensureSublayer()) {
        store.abort();
        return ReplaceResult::kKeptPrevious;
    }
    bool isEveryPermitAdded = true;
    for (const auto &rule : rules) {
        if (!store.add(rule)) {
            if (!rule.isPermitForApps) {
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

} // namespace scoped_permits
