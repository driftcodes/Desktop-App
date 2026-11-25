#pragma once

#include <set>
#include <string>
#include <vector>

#include "types/ipaddress.h"

// Which program-scoped firewall rules to install, kept free of WFP so it can be unit-tested.
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

struct DnsRule
{
    types::IpAddress server;
    bool isPermitForApps;  // false: block port 53 for every program; true: permit the listed programs
};

// DnsFirewall: for each DNS server configured on an adapter (minus the excluded ones), a block of
// port 53 for every program, and, when the permitted programs (Windscribe's own and split-tunnel
// excluded apps) are known, a permit for them that outranks the block. With no programs known only
// the blocks are added.
inline std::vector<DnsRule> dnsFilterRules(const std::set<types::IpAddress> &servers,
                                           const std::set<types::IpAddress> &excluded, size_t permittedAppsCount)
{
    std::vector<DnsRule> rules;
    for (const auto &server : servers) {
        if (excluded.count(server) > 0) {
            continue;
        }
        rules.push_back(DnsRule{server, false});
        if (permittedAppsCount > 0) {
            rules.push_back(DnsRule{server, true});
        }
    }
    return rules;
}

} // namespace scoped_permits
