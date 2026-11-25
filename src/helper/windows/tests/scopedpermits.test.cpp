// Tests for the program-scoped firewall rule plans (scoped_permit_plan.h). No external test framework;
// returns the number of failed checks (0 on success).

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

void testWindscribeOnlyPermitsNeedKnownPrograms()
{
    const std::vector<std::wstring> resolvers = {L"1.1.1.1", L"1.0.0.1", L"76.76.2.0"};
    // Unknown programs: zero permits, never an every-program permit.
    VERIFY(scoped_permits::windscribeOnlyPermits(resolvers, 0).empty());
    // Known programs: every resolver gets its scoped permit.
    VERIFY(scoped_permits::windscribeOnlyPermits(resolvers, 3) == resolvers);
    VERIFY(scoped_permits::windscribeOnlyPermits({}, 3).empty());
}

void testDnsRulesBlockEveryAdapterResolver()
{
    // A Wi-Fi resolver in a private range and a public one, both on the adapter.
    const std::set<types::IpAddress> servers = {types::IpAddress(std::string("192.168.1.1")), types::IpAddress(std::string("1.1.1.1"))};

    const auto withApps = scoped_permits::dnsFilterRules(servers, {}, 2);
    VERIFY(withApps.size() == 4);
    size_t blocks = 0;
    size_t permits = 0;
    for (const auto &rule : withApps) {
        rule.isPermitForApps ? ++permits : ++blocks;
    }
    VERIFY(blocks == 2);
    VERIFY(permits == 2);

    // No programs known: still a block for each resolver, and no permit at all.
    const auto withoutApps = scoped_permits::dnsFilterRules(servers, {}, 0);
    VERIFY(withoutApps.size() == 2);
    for (const auto &rule : withoutApps) {
        VERIFY(!rule.isPermitForApps);
    }

    // An excluded server (e.g. the local custom DNS) gets neither.
    const auto excluded = scoped_permits::dnsFilterRules(servers, {types::IpAddress(std::string("192.168.1.1"))}, 2);
    VERIFY(excluded.size() == 2);
    for (const auto &rule : excluded) {
        VERIFY(rule.server == types::IpAddress(std::string("1.1.1.1")));
    }
}

} // namespace

int main()
{
    testWindscribeOnlyPermitsNeedKnownPrograms();
    testDnsRulesBlockEveryAdapterResolver();
    if (g_failures == 0) {
        printf("All scoped permit tests passed.\n");
    }
    return g_failures;
}
