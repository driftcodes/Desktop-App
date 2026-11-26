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

const uint64_t kWifi = 0x47000000000001ULL;
const uint64_t kUsbEthernet = 0x06000000000002ULL;   // plugged in while Windows was off
const uint64_t kTunnel = 0x35000000000003ULL;        // Windscribe's VPN adapter
const uint64_t kLoopback = 0x18000000000001ULL;

void testBaselineBlocksDnsOnEveryAdapter()
{
    using scoped_permits::baselineAllows;
    const auto rules = scoped_permits::dnsBaselineRules({kTunnel}, {}, 3);

    // nslookup to the router over Wi-Fi, whether or not the Wi-Fi lists it as its DNS server (it
    // does not after switching the Wi-Fi to Google's), and to public resolvers.
    VERIFY(!baselineAllows(rules, kWifi, ip("192.168.31.1"), false));
    VERIFY(!baselineAllows(rules, kWifi, ip("8.8.8.8"), false));
    VERIFY(!baselineAllows(rules, kWifi, ip("1.1.1.1"), false));
    VERIFY(!baselineAllows(rules, kWifi, ip("fe80::1"), false));
    // An adapter nobody told it about is covered too.
    VERIFY(!baselineAllows(rules, kUsbEthernet, ip("192.168.42.129"), false));
    // DNS through the VPN adapter, and to loopback (ctrld), works for every program.
    VERIFY(baselineAllows(rules, kTunnel, ip("10.255.255.1"), false));
    VERIFY(baselineAllows(rules, kTunnel, ip("10.8.0.1"), false));
    VERIFY(baselineAllows(rules, kLoopback, ip("127.0.0.1"), false));
    VERIFY(baselineAllows(rules, kLoopback, ip("::1"), false));
    // Windscribe's programs and excluded apps (Throne) keep DNS on every adapter.
    VERIFY(baselineAllows(rules, kWifi, ip("192.168.31.1"), true));
    VERIFY(baselineAllows(rules, kUsbEthernet, ip("8.8.8.8"), true));

    // No programs known: no permit for them.
    const auto noApps = scoped_permits::dnsBaselineRules({}, {}, 0);
    VERIFY(!baselineAllows(noApps, kWifi, ip("192.168.31.1"), true));

    // Connected with a custom Connected DNS on the LAN: that address is reachable, others are not.
    const auto custom = scoped_permits::dnsBaselineRules({kTunnel}, {ip("192.168.31.1")}, 3);
    VERIFY(baselineAllows(custom, kWifi, ip("192.168.31.1"), false));
    VERIFY(!baselineAllows(custom, kWifi, ip("192.168.31.2"), false));
    VERIFY(!baselineAllows(custom, kWifi, ip("8.8.8.8"), false));
}

void testBaselineAfterReboot()
{
    using scoped_permits::baselineAllows;
    // What was in place while connected: tunnel permit and a custom DNS on the LAN.
    const auto running = scoped_permits::dnsBaselineRules({kTunnel}, {ip("192.168.31.1")}, 3);
    // Only the persistent part survives a reboot.
    const auto atBoot = scoped_permits::persistentBaselineRules(running);
    // Saved while only Wi-Fi existed; at boot Wi-Fi and a USB adapter are present and the GUI has not
    // started: both are blocked for ordinary programs.
    VERIFY(!baselineAllows(atBoot, kWifi, ip("192.168.31.1"), false));
    VERIFY(!baselineAllows(atBoot, kUsbEthernet, ip("192.168.42.129"), false));
    // No stale exception: neither the old custom DNS nor the old tunnel adapter's.
    VERIFY(!baselineAllows(atBoot, kWifi, ip("192.168.31.1"), false));
    VERIFY(!baselineAllows(atBoot, kTunnel, ip("10.255.255.1"), false));
    // Throne (an excluded app saved in the rules) and loopback still work before the GUI starts.
    VERIFY(baselineAllows(atBoot, kWifi, ip("192.168.31.1"), true));
    VERIFY(baselineAllows(atBoot, kLoopback, ip("127.0.0.1"), false));
}

class FakeBaselineStore : public scoped_permits::RuleStore<scoped_permits::BaselineRule>
{
public:
    std::vector<scoped_permits::BaselineRule> committed;
    std::vector<scoped_permits::BaselineRule> working;
    int failAddAt = -1;
    int addCalls = 0;
    bool begin() override { working = committed; return true; }
    bool removeAll() override { working.clear(); return true; }
    bool ensureSublayer() override { return true; }
    bool add(const scoped_permits::BaselineRule &rule) override
    {
        if (addCalls++ == failAddAt) {
            return false;
        }
        working.push_back(rule);
        return true;
    }
    bool commit() override { committed = working; return true; }
    void abort() override { working.clear(); }
};

void testFirstBaselineInstallFails()
{
    using scoped_permits::ReplaceResult;
    // No baseline from before; the first install cannot add its block.
    FakeBaselineStore store;
    store.failAddAt = 0;
    const auto result = scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsBaselineRules({}, {}, 3));
    VERIFY(result == ReplaceResult::kKeptPrevious);
    VERIFY(store.committed.empty());
    const bool isBaselineInPlace = false;
    // firewallOn then holds the LAN permit back and reports the request as incomplete.
    const auto plan = scoped_permits::planFirewallOn(isBaselineInPlace, true);
    VERIFY(plan.holdLanPermit);
    VERIFY(!plan.isComplete);
    // Once it is in: LAN permit back, complete.
    store.failAddAt = -1;
    store.addCalls = 0;
    VERIFY(scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsBaselineRules({}, {}, 3)) ==
           ReplaceResult::kApplied);
    const auto ready = scoped_permits::planFirewallOn(true, true);
    VERIFY(!ready.holdLanPermit);
    VERIFY(ready.isComplete);
    // A main firewall that is incomplete for its own reasons stays reported as such.
    VERIFY(!scoped_permits::planFirewallOn(true, false).isComplete);

    // A later failed rebuild keeps the rules in place.
    store.addCalls = 0;
    store.failAddAt = 0;
    VERIFY(scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsBaselineRules({kTunnel}, {}, 3)) ==
           ReplaceResult::kKeptPrevious);
    VERIFY(!scoped_permits::baselineAllows(store.committed, kWifi, ip("192.168.31.1"), false));
}

void testStartupVerifiesSavedBaseline()
{
    using scoped_permits::BaselineAtStart;
    using scoped_permits::InstalledFilter;
    // The first version's per-adapter block (an interface condition) is not the global block.
    InstalledFilter perAdapter = {true, true, true, true, false, false};
    VERIFY(!scoped_permits::isGlobalBaselineBlock(perAdapter));
    // Nor is a permit, an address-scoped or program-scoped rule, or a non-persistent one.
    VERIFY(!scoped_permits::isGlobalBaselineBlock({false, true, true, false, false, false}));
    VERIFY(!scoped_permits::isGlobalBaselineBlock({true, true, true, false, true, false}));
    VERIFY(!scoped_permits::isGlobalBaselineBlock({true, true, true, false, false, true}));
    VERIFY(!scoped_permits::isGlobalBaselineBlock({true, false, true, false, false, false}));
    VERIFY(scoped_permits::isGlobalBaselineBlock({true, true, true, false, false, false}));

    // Saved rules for adapter A only (or the first version's), adapters A and B present, no GUI:
    // not both global blocks found, so a baseline is built instead of trusting them.
    VERIFY(scoped_permits::planBaselineAtStart(false, false) == BaselineAtStart::kBuild);
    VERIFY(scoped_permits::planBaselineAtStart(true, false) == BaselineAtStart::kBuild);
    VERIFY(scoped_permits::planBaselineAtStart(true, true) == BaselineAtStart::kKeepSaved);

    // The firewall survived (Always On) but no baseline, and building one fails, before the GUI:
    // the LAN permit is held (FirewallFilter::holdLanPermit), as for a failed firewallOn.
    FakeBaselineStore store;
    store.failAddAt = 0;
    VERIFY(scoped_permits::replaceDnsRules(store, true, scoped_permits::dnsBaselineRules({}, {}, 3)) ==
           scoped_permits::ReplaceResult::kKeptPrevious);
    VERIFY(scoped_permits::planFirewallOn(false, true).holdLanPermit);
}

void testStaleReadyCallbackDoesNotRestoreLan()
{
    // Activation 1's baseline gets in; before its callback runs, the firewall is turned off and on
    // (activation 2) and activation 2's baseline fails, so its LAN permit is held. The late callback
    // must not restore it.
    const bool isRequestHeld = true;      // activation 2's request
    const bool isFirewallOn = true;
    const bool isBaselineInPlaceNow = false;
    VERIFY(!scoped_permits::shouldRestoreLanPermit(isRequestHeld, isFirewallOn, isBaselineInPlaceNow));
    // Once activation 2's baseline does get in, it is restored.
    VERIFY(scoped_permits::shouldRestoreLanPermit(true, true, true));
    // Nothing held, or the firewall off: nothing to restore.
    VERIFY(!scoped_permits::shouldRestoreLanPermit(false, true, true));
    VERIFY(!scoped_permits::shouldRestoreLanPermit(true, false, true));
}

void testMigrationKeepsOldBlockUntilNewCommitted()
{
    using scoped_permits::BaselineAction;
    using scoped_permits::BaselineRule;
    using scoped_permits::ReplaceResult;
    // The first version's rules: per-adapter blocks on Wi-Fi only. The real store removes them in the
    // same transaction as the new rules go in (its removeAll covers the old sublayer too).
    const std::vector<BaselineRule> legacy = {
        BaselineRule{BaselineAction::kBlock, false, kWifi, types::IpAddressRange(), true},
        BaselineRule{BaselineAction::kBlock, true, kWifi, types::IpAddressRange(), true}};
    const auto newRules = scoped_permits::dnsBaselineRules({}, {}, 3);

    // The new blocks cannot be added: aborted, the old ones are still there, router DNS blocked.
    FakeBaselineStore store;
    store.committed = legacy;
    store.failAddAt = 0;
    VERIFY(scoped_permits::replaceDnsRules(store, true, newRules) == ReplaceResult::kKeptPrevious);
    VERIFY(!scoped_permits::baselineAllows(store.committed, kWifi, ip("192.168.31.1"), false));
    // Fails at the last block (v6) too.
    store.addCalls = 0;
    store.failAddAt = 3;  // v4 block, v4 programs, v4 loopback, v6 block
    VERIFY(!scoped_permits::isBlockRule(newRules[2]));
    VERIFY(scoped_permits::isBlockRule(newRules[3]));
    VERIFY(scoped_permits::replaceDnsRules(store, true, newRules) == ReplaceResult::kKeptPrevious);
    VERIFY(store.committed.size() == legacy.size());
    VERIFY(!scoped_permits::baselineAllows(store.committed, kWifi, ip("192.168.31.1"), false));

    // They go in: one commit swaps old for new, so there is no state without a block in between,
    // and now the second adapter is covered too.
    store.addCalls = 0;
    store.failAddAt = -1;
    VERIFY(scoped_permits::replaceDnsRules(store, true, newRules) == ReplaceResult::kApplied);
    VERIFY(!scoped_permits::baselineAllows(store.committed, kWifi, ip("192.168.31.1"), false));
    VERIFY(!scoped_permits::baselineAllows(store.committed, kUsbEthernet, ip("192.168.31.1"), false));
}

void testMainFirewallCommitNeedsBothDefaultBlocks()
{
    using scoped_permits::planFirewallApply;
    // The IPv4 block-all cannot be added: aborted, the previous rules stay, reported incomplete.
    auto plan = planFirewallApply(true, false, true, true);
    VERIFY(!plan.commit);
    VERIFY(!plan.isComplete);
    // The IPv6 one.
    plan = planFirewallApply(true, true, false, true);
    VERIFY(!plan.commit);
    VERIFY(!plan.isComplete);
    // The transaction could not begin.
    plan = planFirewallApply(false, true, true, true);
    VERIFY(!plan.commit);
    // Both in: committed; complete unless a permit was missing (fails closed). A failed commit makes
    // it incomplete whatever this says (FirewallFilter::on: isCommitted && plan.isComplete).
    plan = planFirewallApply(true, true, true, true);
    VERIFY(plan.commit && plan.isComplete);
    plan = planFirewallApply(true, true, true, false);
    VERIFY(plan.commit && !plan.isComplete);
    const bool isCommitted = false;
    VERIFY(!(isCommitted && planFirewallApply(true, true, true, true).isComplete));
}

// Windows' filters by id, with a transaction, as the helper's FirewallFilter uses them.
struct FakeWfp
{
    std::set<uint64_t> installed;
    std::set<uint64_t> working;
    uint64_t nextId = 100;
    void begin() { working = installed; }
    uint64_t add()
    {
        working.insert(nextId);
        return nextId++;
    }
    bool remove(uint64_t id) { return working.erase(id) == 1; }
    void commit() { installed = working; }
    void abort() { working = installed; }
};

void testFailedRebuildKeepsSplitTunnelIds()
{
    // Installed: the split-tunnel permits for Throne (app) and its VLESS server (IP).
    FakeWfp wfp;
    std::vector<uint64_t> appIds;
    std::vector<uint64_t> ipIds;
    wfp.begin();
    appIds.push_back(wfp.add());
    ipIds.push_back(wfp.add());
    wfp.commit();

    // A firewall rebuild: the old filters out, the new in (ids recorded), then it does not commit.
    {
        scoped_permits::FilterIdsSnapshot<std::vector<uint64_t>> snapshot({&appIds, &ipIds});
        wfp.begin();
        for (const uint64_t id : appIds) wfp.remove(id);
        for (const uint64_t id : ipIds) wfp.remove(id);
        appIds = {wfp.add()};
        ipIds = {wfp.add()};
        wfp.abort();
        snapshot.rollback();
    }
    VERIFY(wfp.installed.size() == 2);

    // Later the user removes Throne and the VLESS IP from the exclusions: both permits must go.
    wfp.begin();
    bool isRemoved = true;
    for (const uint64_t id : appIds) isRemoved = wfp.remove(id) && isRemoved;
    for (const uint64_t id : ipIds) isRemoved = wfp.remove(id) && isRemoved;
    wfp.commit();
    VERIFY(isRemoved);
    VERIFY(wfp.installed.empty());
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
    testBaselineBlocksDnsOnEveryAdapter();
    testBaselineAfterReboot();
    testFirstBaselineInstallFails();
    testStartupVerifiesSavedBaseline();
    testStaleReadyCallbackDoesNotRestoreLan();
    testMigrationKeepsOldBlockUntilNewCommitted();
    testMainFirewallCommitNeedsBothDefaultBlocks();
    testFailedRebuildKeepsSplitTunnelIds();
    if (g_failures == 0) {
        printf("All scoped permit tests passed.\n");
    }
    return g_failures;
}
