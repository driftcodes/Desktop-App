// Tests for the program-scoped firewall rule plans and the DNS leak filter's rule replacement
// (scoped_permit_plan.h). No external test framework; returns the number of failed checks.

#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "scoped_permit_plan.h"

namespace
{

int g_failures = 0;

bool check(bool ok, const char *expr, int line)
{
    if (!ok) {
        ++g_failures;
        printf("FAIL (line %d): %s\n", line, expr);
    }
    return ok;
}

#define VERIFY(expr) check(!!(expr), #expr, __LINE__)

using scoped_permits::DnsRule;
using types::IpAddress;
using types::IpAddressRange;

IpAddress ip(const char *s)
{
    return IpAddress(std::string(s));
}

// Does some block (or permit) rule cover addr?
bool covers(const std::vector<DnsRule> &rules, const IpAddress &addr, bool permit)
{
    for (const auto &rule : rules) {
        if (rule.isPermitForApps == permit && scoped_permits::rangeContains(rule.target, addr)) {
            return true;
        }
    }
    return false;
}

size_t countPermits(const std::vector<DnsRule> &rules)
{
    size_t n = 0;
    for (const auto &rule : rules) {
        n += rule.isPermitForApps ? 1 : 0;
    }
    return n;
}

void testWindscribeOnlyPermitsNeedKnownPrograms()
{
    const std::vector<std::wstring> resolvers = {L"1.1.1.1", L"1.0.0.1", L"76.76.2.0"};
    // Unknown programs: zero permits, never an every-program permit.
    VERIFY(scoped_permits::windscribeOnlyPermits(resolvers, 0).empty());
    // Known programs: every resolver gets its scoped permit.
    VERIFY(scoped_permits::windscribeOnlyPermits(resolvers, 3) == resolvers);
    VERIFY(scoped_permits::windscribeOnlyPermits({}, 3).empty());
}

void testRangeContains()
{
    VERIFY(scoped_permits::rangeContains(IpAddressRange(std::string("172.16.0.0/12")), ip("172.31.255.1")));
    VERIFY(!scoped_permits::rangeContains(IpAddressRange(std::string("172.16.0.0/12")), ip("172.32.0.1")));
    VERIFY(scoped_permits::rangeContains(IpAddressRange(std::string("fe80::/10")), ip("fe80::1")));
    VERIFY(!scoped_permits::rangeContains(IpAddressRange(std::string("192.168.0.0/16")), ip("fe80::1")));
}

void testNotConnectedRulesCoverWifiRouterAndCloudflare()
{
    // Wi-Fi with router A as its resolver, plus Cloudflare on the adapter.
    const std::set<IpAddress> servers = {ip("192.168.1.1"), ip("1.1.1.1")};
    const auto rules = scoped_permits::dnsFilterRules(servers, {}, true, 2);
    VERIFY(covers(rules, ip("192.168.1.1"), false));
    VERIFY(covers(rules, ip("1.1.1.1"), false));
    // Router B on the network joined next is blocked before its address was ever read.
    VERIFY(covers(rules, ip("192.168.50.1"), false));
    VERIFY(covers(rules, ip("10.0.0.1"), false));
    VERIFY(covers(rules, ip("fe80::1"), false));
    // Every block has its permit for Windscribe's programs and excluded apps.
    VERIFY(covers(rules, ip("192.168.50.1"), true));
    VERIFY(covers(rules, ip("1.1.1.1"), true));
    VERIFY(countPermits(rules) * 2 == rules.size());
    // A public address that is not a resolver here is left to the main firewall.
    VERIFY(!covers(rules, ip("8.8.8.8"), false));

    // No programs known: the same blocks and no permit at all.
    const auto noApps = scoped_permits::dnsFilterRules(servers, {}, true, 0);
    VERIFY(countPermits(noApps) == 0);
    VERIFY(covers(noApps, ip("192.168.50.1"), false));
    VERIFY(covers(noApps, ip("1.1.1.1"), false));
}

void testCustomDnsExclusionOnlyWhileConnected()
{
    const std::set<IpAddress> servers = {ip("192.168.1.1"), ip("1.1.1.1")};
    const std::set<IpAddress> customDns = {ip("192.168.1.1")};
    // Connected, as upstream: the user's custom connected DNS is not blocked; nothing is permitted.
    const auto connected = scoped_permits::dnsFilterRules(servers, customDns, false, 2);
    VERIFY(!covers(connected, ip("192.168.1.1"), false));
    VERIFY(covers(connected, ip("1.1.1.1"), false));
    VERIFY(countPermits(connected) == 0);
    // Not connected under a proxy: the same router is blocked for every other program.
    const auto notConnected = scoped_permits::dnsFilterRules(servers, customDns, true, 2);
    VERIFY(covers(notConnected, ip("192.168.1.1"), false));

    // Same with a public custom DNS that is also on the adapter (outside the local ranges).
    const std::set<IpAddress> publicCustomDns = {ip("1.1.1.1")};
    VERIFY(!covers(scoped_permits::dnsFilterRules(servers, publicCustomDns, false, 2), ip("1.1.1.1"), false));
    VERIFY(covers(scoped_permits::dnsFilterRules(servers, publicCustomDns, true, 2), ip("1.1.1.1"), false));
}

// A WFP stand-in: committed rules, and a transaction that holds a working copy.
class FakeStore : public scoped_permits::DnsRuleStore
{
public:
    std::vector<DnsRule> committed;
    std::vector<DnsRule> working;
    bool inTransaction = false;
    bool failBegin = false;
    bool failCommit = false;
    int failAddAt = -1;  // index of the add() call that fails
    int addCalls = 0;

    bool begin() override
    {
        if (failBegin) {
            return false;
        }
        working = committed;
        inTransaction = true;
        return true;
    }
    bool removeAll() override
    {
        working.clear();
        return true;
    }
    bool ensureSublayer() override { return true; }
    bool add(const DnsRule &rule) override
    {
        if (addCalls++ == failAddAt) {
            return false;
        }
        working.push_back(rule);
        return true;
    }
    bool commit() override
    {
        if (failCommit) {
            return false;
        }
        committed = working;
        inTransaction = false;
        return true;
    }
    void abort() override
    {
        working.clear();
        inTransaction = false;
    }
};

void testFailedReplacementKeepsWorkingRouterBlock()
{
    using scoped_permits::ReplaceResult;
    FakeStore store;
    // A working block for router A.
    const auto routerA = scoped_permits::dnsFilterRules({ip("192.168.1.1")}, {}, false, 0);
    VERIFY(scoped_permits::replaceDnsRules(store, true, routerA) == ReplaceResult::kApplied);
    VERIFY(covers(store.committed, ip("192.168.1.1"), false));

    const auto replacement = scoped_permits::dnsFilterRules({ip("192.168.1.1"), ip("1.1.1.1")}, {}, true, 2);

    // Nothing reliable to apply (adapters unreadable while connected): nothing is touched.
    VERIFY(scoped_permits::replaceDnsRules(store, false, replacement) == ReplaceResult::kKeptPrevious);
    VERIFY(store.committed.size() == routerA.size());
    VERIFY(covers(store.committed, ip("192.168.1.1"), false));

    // A block cannot be added: aborted, router A's block stays.
    store.addCalls = 0;
    store.failAddAt = 2;
    VERIFY(!replacement[2].isPermitForApps);
    VERIFY(scoped_permits::replaceDnsRules(store, true, replacement) == ReplaceResult::kKeptPrevious);
    VERIFY(!store.inTransaction);
    VERIFY(store.committed.size() == routerA.size());
    VERIFY(covers(store.committed, ip("192.168.1.1"), false));

    // The commit fails: the same.
    store.addCalls = 0;
    store.failAddAt = -1;
    store.failCommit = true;
    VERIFY(scoped_permits::replaceDnsRules(store, true, replacement) == ReplaceResult::kKeptPrevious);
    VERIFY(store.committed.size() == routerA.size());
    store.failCommit = false;

    // The transaction cannot start: the same.
    store.failBegin = true;
    VERIFY(scoped_permits::replaceDnsRules(store, true, replacement) == ReplaceResult::kKeptPrevious);
    VERIFY(store.committed.size() == routerA.size());
    store.failBegin = false;

    // Only a permit fails: the blocks go in (fail closed) and the caller is told to retry.
    store.addCalls = 0;
    store.failAddAt = 1;
    VERIFY(replacement[1].isPermitForApps);
    VERIFY(scoped_permits::replaceDnsRules(store, true, replacement) == ReplaceResult::kAppliedWithoutSomePermits);
    VERIFY(covers(store.committed, ip("192.168.50.1"), false));
    VERIFY(store.committed.size() == replacement.size() - 1);

    // A network with no DNS servers is a valid result, not an error.
    store.failAddAt = -1;
    VERIFY(scoped_permits::replaceDnsRules(store, true, {}) == ReplaceResult::kApplied);
    VERIFY(store.committed.empty());
}

void testFirstEnableWithUnreadableAdaptersStillBlocks()
{
    using scoped_permits::ReplaceResult;
    // Empty rule store (first connection) and the adapters cannot be read.
    FakeStore store;
    const auto plan = scoped_permits::planDnsRules(false, {}, {}, {}, true, 2);
    VERIFY(plan.canApply);
    VERIFY(plan.isFallback);
    VERIFY(scoped_permits::replaceDnsRules(store, plan.canApply, plan.rules) == ReplaceResult::kApplied);
    // The Wi-Fi router is blocked for other programs all the same.
    VERIFY(covers(store.committed, ip("192.168.1.1"), false));
    VERIFY(covers(store.committed, ip("10.0.0.138"), false));
    VERIFY(covers(store.committed, ip("192.168.1.1"), true));

    // With resolvers known from before, those stay blocked too (Cloudflare on the adapter).
    const auto withLastKnown = scoped_permits::planDnsRules(false, {}, {ip("1.1.1.1")}, {}, true, 2);
    VERIFY(covers(withLastKnown.rules, ip("1.1.1.1"), false));

    // While connected, unreadable adapters keep the rules in place instead.
    VERIFY(!scoped_permits::planDnsRules(false, {}, {ip("192.168.1.1")}, {}, false, 0).canApply);

    // Empty rule store and a block that cannot be added: still nothing, and the caller is told.
    FakeStore failing;
    failing.failAddAt = 0;
    VERIFY(scoped_permits::replaceDnsRules(failing, plan.canApply, plan.rules) == ReplaceResult::kKeptPrevious);
    VERIFY(failing.committed.empty());
}

void testResolverChangeOnSameWifiWhileConnected()
{
    using scoped_permits::ReplaceResult;
    // Connected; the rules block router A (the connected rules list resolvers one by one).
    FakeStore store;
    const std::set<IpAddress> before = {ip("192.168.1.1")};
    VERIFY(scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsFilterRules(before, {}, false, 0)) ==
           ReplaceResult::kApplied);
    VERIFY(!covers(store.committed, ip("192.168.1.53"), false));

    // DHCP renewal on the same Wi-Fi hands out 192.168.1.53 instead: same adapter, same network.
    const std::set<IpAddress> after = {ip("192.168.1.53")};
    VERIFY(scoped_permits::dnsServersChanged(true, after, before));
    VERIFY(scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsFilterRules(after, {}, false, 0)) ==
           ReplaceResult::kApplied);
    VERIFY(covers(store.committed, ip("192.168.1.53"), false));

    // Nothing to do when nothing changed, or when the adapters cannot be read.
    VERIFY(!scoped_permits::dnsServersChanged(true, after, after));
    VERIFY(!scoped_permits::dnsServersChanged(false, {}, after));
}

void testRemovedExclusionRetriedAfterFailedRebuild()
{
    using Apps = std::vector<std::wstring>;
    scoped_permits::PermittedAppsTracker<Apps> tracker;
    const Apps withEdge = {L"windscribe.exe", L"throne.exe", L"msedge.exe"};
    const Apps withoutEdge = {L"windscribe.exe", L"throne.exe"};

    VERIFY(tracker.request(withEdge));  // nothing applied yet
    tracker.onApplied();
    VERIFY(!tracker.request(withEdge));  // same list, rules match

    // Edge removed from the exclusions; the rebuild fails, so the old permit (with Edge) stays.
    VERIFY(tracker.request(withoutEdge));
    // The identical list sent again must still rebuild.
    VERIFY(tracker.request(withoutEdge));
    VERIFY(tracker.needsRebuild());
    tracker.onApplied();
    VERIFY(!tracker.request(withoutEdge));

    // Rules without permits in place (connected): any list differs from them.
    tracker.onNoPermitsInPlace();
    VERIFY(tracker.needsRebuild());
}

void testRejectedRequestKeepsOwnersExceptions()
{
    scoped_permits::DnsFilterRequests requests;
    // The engine holds the filter for a proxied session, with no custom DNS exception.
    VERIFY(requests.acceptEnable(DnsLeakFilterOwner::kProxiedSession, true, {}));
    // The previous session's connector asks to enable with its own exception list: rejected, and
    // nothing it carried is taken.
    VERIFY(!requests.acceptEnable(DnsLeakFilterOwner::kConnection, false, {ip("192.168.1.1")}));
    VERIFY(requests.excluded().empty());
    VERIFY(requests.permitApps());
    VERIFY(requests.isWanted());
    // Its disable is rejected too.
    VERIFY(!requests.acceptDisable(DnsLeakFilterOwner::kConnection));
    VERIFY(requests.isWanted());
    // So a later rebuild (e.g. after a resolver change) still blocks that router.
    const auto rules = scoped_permits::dnsFilterRules({ip("192.168.1.1")}, requests.excluded(), false, 0);
    VERIFY(covers(rules, ip("192.168.1.1"), false));

    // The owner's own request does change them.
    VERIFY(requests.acceptEnable(DnsLeakFilterOwner::kProxiedSession, false, {ip("1.1.1.1")}));
    VERIFY(requests.excluded().count(ip("1.1.1.1")) == 1);
    VERIFY(!requests.permitApps());
}

} // namespace

int main()
{
    testWindscribeOnlyPermitsNeedKnownPrograms();
    testRangeContains();
    testNotConnectedRulesCoverWifiRouterAndCloudflare();
    testCustomDnsExclusionOnlyWhileConnected();
    testFailedReplacementKeepsWorkingRouterBlock();
    testFirstEnableWithUnreadableAdaptersStillBlocks();
    testResolverChangeOnSameWifiWhileConnected();
    testRemovedExclusionRetriedAfterFailedRebuild();
    testRejectedRequestKeepsOwnersExceptions();
    if (g_failures == 0) {
        printf("All scoped permit tests passed.\n");
    }
    return g_failures;
}
