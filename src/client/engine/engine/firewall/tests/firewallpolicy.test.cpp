#include "firewallpolicy.test.h"

#include <QtTest>

#include "engine/firewall/firewallcontroller.h"
#include "engine/firewall/firewallexceptions.h"
#include "engine/firewall/firewallpolicy.h"
#include "types/proxysettings.h"
#include "utils/hardcodedsettings.h"

namespace {

// Records what the engine asks of the firewall.
class FakeFirewallController : public FirewallController
{
public:
    explicit FakeFirewallController(bool isOn) : FirewallController(nullptr), isOn_(isOn) {}

    void firewallOn(const QString &connectingIp, const QSet<QString> &ips, bool, bool, bool isVpnConnected,
                    const QSet<QString> &windscribeOnlyIps) override
    {
        isOn_ = true;
        ++onCalls;
        lastConnectingIp = connectingIp;
        lastIps = ips;
        lastWindscribeOnlyIps = windscribeOnlyIps;
        lastIsVpnConnected = isVpnConnected;
    }
    void firewallOff() override
    {
        isOn_ = false;
        ++offCalls;
    }
    bool firewallActualState() override { return isOn_; }
    void setVpnInterface_posix(const QString &) override {}
    void setFirewallOnBoot(bool, const QSet<QString> &, bool) override {}

    int onCalls = 0;
    int offCalls = 0;
    QString lastConnectingIp;
    QSet<QString> lastIps;
    QSet<QString> lastWindscribeOnlyIps;
    bool lastIsVpnConnected = true;

private:
    bool isOn_;
};

FirewallExceptions makeExceptions(bool withProxy)
{
    FirewallExceptions exceptions;
    exceptions.setDnsPolicy(DNS_TYPE_CLOUDFLARE);
    exceptions.setHostIPs(QSet<QString>{"104.20.0.1"});
    exceptions.setLocationsPingIps(QStringList{"185.1.1.1"});
    exceptions.setCustomConfigPingIps(QStringList{"5.6.7.8"});
    if (withProxy) {
        exceptions.setProxyIP(types::ProxySettings(PROXY_OPTION_HTTP, "127.0.0.1", 2080, "", ""));
    }
    return exceptions;
}

} // namespace

void TestFirewallPolicy::testNotConnectedExceptionsUnderProxy()
{
    const FirewallExceptions exceptions = makeExceptions(true);
    QVERIFY(exceptions.isProxySet());
    const QSet<QString> ips = exceptions.getIPAddressesForNotConnectedState(false, false);

    QVERIFY(ips.contains("127.0.0.1"));
    // DNS stays: wsnet resolves API hostnames itself even through a proxy.
    for (const QString &dns : HardcodedSettings::instance().cloudflareDns()) {
        QVERIFY(ips.contains(dns));
    }
    // No direct permits for the API hosts or ping targets while the tunnel is down.
    QVERIFY(!ips.contains("104.20.0.1"));
    QVERIFY(!ips.contains("185.1.1.1"));
    QVERIFY(!ips.contains("5.6.7.8"));

    // Always On+ keeps its own (connected-state) list.
    QCOMPARE(exceptions.getIPAddressesForNotConnectedState(true, false), exceptions.getIPAddressesForFirewallForConnectedState());
    QVERIFY(exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, false).isEmpty());

    // Windows: the DNS servers move to the Windscribe-only list, so other programs cannot reach them.
    const QSet<QString> scoped = exceptions.getIPAddressesForNotConnectedState(false, true);
    const QSet<QString> windscribeOnly = exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true);
    QVERIFY(scoped.contains("127.0.0.1"));
    for (const QString &dns : HardcodedSettings::instance().cloudflareDns()) {
        QVERIFY(!scoped.contains(dns));
        QVERIFY(windscribeOnly.contains(dns));
    }
    for (const QString &controld : HardcodedSettings::instance().controldDns()) {
        QVERIFY(!scoped.contains(controld));
        QVERIFY(windscribeOnly.contains(controld));
    }
    QVERIFY(!windscribeOnly.contains("104.20.0.1"));
    QVERIFY(!windscribeOnly.contains("127.0.0.1"));
    // Always On+ scopes nothing (its list has no DNS servers at all).
    QVERIFY(exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(true, true).isEmpty());
}

void TestFirewallPolicy::testNotConnectedExceptionsWithoutProxy()
{
    const FirewallExceptions exceptions = makeExceptions(false);
    QVERIFY(!exceptions.isProxySet());
    QCOMPARE(exceptions.getIPAddressesForNotConnectedState(false, false), exceptions.getIPAddressesForFirewall());
    // Without a proxy nothing is scoped, even on Windows: upstream behaviour.
    QCOMPARE(exceptions.getIPAddressesForNotConnectedState(false, true), exceptions.getIPAddressesForFirewall());
    QVERIFY(exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true).isEmpty());
    QVERIFY(exceptions.getIPAddressesForFirewall().contains("104.20.0.1"));
}

void TestFirewallPolicy::testLeaveConnectionForgetsEndpointAndKeepsFirewallOn()
{
    FirewallExceptions exceptions = makeExceptions(true);
    bool changed = false;
    exceptions.setConnectingIp("203.0.113.7", changed);
    exceptions.setDNSServers(QStringList{"10.8.0.1"}, changed);

    FakeFirewallController controller(true);
    firewall_policy::leaveConnection(controller, exceptions,
                                     [&exceptions]() { return exceptions.getIPAddressesForNotConnectedState(false, true); },
                                     [&exceptions]() { return exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true); },
                                     true, true);

    QVERIFY(exceptions.connectingIp().isEmpty());
    QVERIFY(controller.firewallActualState());
    QCOMPARE(controller.offCalls, 0);
    QCOMPARE(controller.onCalls, 1);
    QVERIFY(controller.lastConnectingIp.isEmpty());
    QVERIFY(!controller.lastIsVpnConnected);
    QVERIFY(!controller.lastIps.contains("203.0.113.7"));
    QVERIFY(!controller.lastIps.contains("10.8.0.1"));
    // The DNS servers reach the helper as Windscribe-only, not as an every-program permit.
    for (const QString &dns : HardcodedSettings::instance().cloudflareDns()) {
        QVERIFY(controller.lastWindscribeOnlyIps.contains(dns));
        QVERIFY(!controller.lastIps.contains(dns));
    }
}

void TestFirewallPolicy::testLeaveConnectionLeavesFirewallOff()
{
    FirewallExceptions exceptions = makeExceptions(true);
    bool changed = false;
    exceptions.setConnectingIp("203.0.113.7", changed);

    FakeFirewallController controller(false);
    firewall_policy::leaveConnection(controller, exceptions,
                                     [&exceptions]() { return exceptions.getIPAddressesForNotConnectedState(false, true); },
                                     [&exceptions]() { return exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true); },
                                     true, true);

    QVERIFY(exceptions.connectingIp().isEmpty());
    QVERIFY(!controller.firewallActualState());
    QCOMPARE(controller.onCalls, 0);
}

void TestFirewallPolicy::testAfterConnectedDecision()
{
    using firewall_policy::AutomaticAction;
    using firewall_policy::afterConnected;

    // Automatic / before connection: a full tunnel keeps the firewall; a split one turns it off.
    QCOMPARE(afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_BEFORE_CONNECTION, true, true), AutomaticAction::None);
    QCOMPARE(afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_BEFORE_CONNECTION, true, false), AutomaticAction::TurnOff);
    // Automatic / after connection: only a full tunnel turns it on.
    QCOMPARE(afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_AFTER_CONNECTION, false, true), AutomaticAction::TurnOn);
    QCOMPARE(afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_AFTER_CONNECTION, false, false), AutomaticAction::None);
    QCOMPARE(afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_AFTER_CONNECTION, true, true), AutomaticAction::None);
    // The other modes never change it here.
    for (FIREWALL_MODE mode : {FIREWALL_MODE_MANUAL, FIREWALL_MODE_ALWAYS_ON, FIREWALL_MODE_ALWAYS_ON_PLUS}) {
        QCOMPARE(afterConnected(mode, FIREWALL_WHEN_BEFORE_CONNECTION, true, false), AutomaticAction::None);
        QCOMPARE(afterConnected(mode, FIREWALL_WHEN_AFTER_CONNECTION, false, true), AutomaticAction::None);
    }
}

void TestFirewallPolicy::testProxiedDnsLeakFilterSpansReconnect()
{
    using namespace firewall_policy;
    // Connect, drop (Wi-Fi), reconnect, location change, then the user's disconnect, as the state
    // controller reports them: CONNECTING once per connect or reconnect, never twice in a row. The
    // filter must never be off in between, also where the old OpenVPN process has exited and the next
    // has not started.
    const CONNECT_STATE sequence[] = {CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED,
                                      CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED,      // reconnect
                                      CONNECT_STATE_DISCONNECTING, CONNECT_STATE_CONNECTING,  // location change
                                      CONNECT_STATE_CONNECTED,  CONNECT_STATE_DISCONNECTING};
    const DnsLeakFilter expected[] = {DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kBlockAll,
                                      DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kBlockAll,
                                      DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kPermitWindscribeApps,
                                      DnsLeakFilter::kBlockAll,             DnsLeakFilter::kPermitWindscribeApps};
    DnsLeakFilter filter = DnsLeakFilter::kOff;
    for (size_t i = 0; i < sizeof(sequence) / sizeof(sequence[0]); ++i) {
        // The proxy being turned off mid-session does not drop the filter either.
        const auto step = proxiedDnsLeakFilter(filter, sequence[i], i < 3);
        filter = step.next;
        QCOMPARE(filter, expected[i]);
        if (sequence[i] == CONNECT_STATE_CONNECTING) {
            QVERIFY(step.apply);
        }
    }
    const auto last = proxiedDnsLeakFilter(filter, CONNECT_STATE_DISCONNECTED, false);
    QCOMPARE(last.next, DnsLeakFilter::kOff);
    QVERIFY(last.apply);
    // A connect refused before any attempt (e.g. UDP-only profile) also ends with the filter off.
    auto refused = proxiedDnsLeakFilter(DnsLeakFilter::kOff, CONNECT_STATE_CONNECTING, true);
    refused = proxiedDnsLeakFilter(refused.next, CONNECT_STATE_DISCONNECTED, true);
    QCOMPARE(refused.next, DnsLeakFilter::kOff);
    QVERIFY(refused.apply);
}

void TestFirewallPolicy::testDnsLeakFilterRebuiltOnNetworkChangeWhileConnecting()
{
    using namespace firewall_policy;
    // Wi-Fi drops while connected: CONNECTING. Wi-Fi returns with router B as its resolver while the
    // state stays CONNECTING; only the network change can rebuild the filter for B.
    auto step = proxiedDnsLeakFilter(DnsLeakFilter::kBlockAll, CONNECT_STATE_CONNECTING, true);
    QCOMPARE(step.next, DnsLeakFilter::kPermitWindscribeApps);
    step = proxiedDnsLeakFilterOnNetworkChange(step.next);
    QCOMPARE(step.next, DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(step.apply);
    // Also while kept after an error, and while connected.
    QVERIFY(proxiedDnsLeakFilterOnNetworkChange(DnsLeakFilter::kBlockAll).apply);
    // Nothing to rebuild when the filter is not the engine's.
    QVERIFY(!proxiedDnsLeakFilterOnNetworkChange(DnsLeakFilter::kOff).apply);
}

void TestFirewallPolicy::testDnsLeakFilterUntouchedWithoutProxy()
{
    using namespace firewall_policy;
    // Without a proxy the engine leaves the filter to each connection, as in the official app.
    for (CONNECT_STATE state : {CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED, CONNECT_STATE_DISCONNECTING,
                                CONNECT_STATE_DISCONNECTED}) {
        const auto step = proxiedDnsLeakFilter(DnsLeakFilter::kOff, state, false);
        QCOMPARE(step.next, DnsLeakFilter::kOff);
        QVERIFY(!step.apply);
    }
}

void TestFirewallPolicy::testDnsLeakFilterKeptAfterErrorUntilFirewallOff()
{
    using namespace firewall_policy;
    // Throne stopped: the reconnect's proxy check fails and the session ends with an error while the
    // firewall stays on. The filter stays, still letting Windscribe's programs and Throne resolve.
    auto step = proxiedDnsLeakFilter(DnsLeakFilter::kPermitWindscribeApps, CONNECT_STATE_DISCONNECTED, true, true);
    QCOMPARE(step.next, DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(!step.apply);
    step = proxiedDnsLeakFilter(DnsLeakFilter::kBlockAll, CONNECT_STATE_DISCONNECTED, true, true);
    QCOMPARE(step.next, DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(step.apply);

    // Turning the firewall off while disconnected removes it ...
    step = proxiedDnsLeakFilterAfterFirewallOff(DnsLeakFilter::kPermitWindscribeApps, CONNECT_STATE_DISCONNECTED);
    QCOMPARE(step.next, DnsLeakFilter::kOff);
    QVERIFY(step.apply);
    // ... but not during a session (Automatic mode can turn the firewall off once connected).
    for (CONNECT_STATE state : {CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED, CONNECT_STATE_DISCONNECTING}) {
        step = proxiedDnsLeakFilterAfterFirewallOff(DnsLeakFilter::kBlockAll, state);
        QCOMPARE(step.next, DnsLeakFilter::kBlockAll);
        QVERIFY(!step.apply);
    }
    step = proxiedDnsLeakFilterAfterFirewallOff(DnsLeakFilter::kOff, CONNECT_STATE_DISCONNECTED);
    QVERIFY(!step.apply);
}

namespace {

// The helper as the controller sees it: scripted answers, a log of what was sent, and the retries
// scheduled (token, delay) for the test to fire whenever it likes.
struct FakeDnsLeakFilterHelper
{
    QList<firewall_policy::DnsLeakFilterSendResult> answers;  // consumed in order; then kApplied
    QList<firewall_policy::DnsLeakFilter> sent;
    QList<QPair<quint64, int>> retries;
    // What the real helper's filter is: the last filter applied, by the engine or by a connector.
    firewall_policy::DnsLeakFilter inPlace = firewall_policy::DnsLeakFilter::kOff;

    firewall_policy::ProxiedDnsLeakFilter makeController()
    {
        return firewall_policy::ProxiedDnsLeakFilter(
            [this](firewall_policy::DnsLeakFilter f) {
                sent << f;
                const auto answer = answers.isEmpty() ? firewall_policy::DnsLeakFilterSendResult::kApplied
                                                      : answers.takeFirst();
                if (answer != firewall_policy::DnsLeakFilterSendResult::kFailed) {
                    inPlace = f;
                }
                return answer;
            },
            [this](quint64 token, int delayMs) { retries << qMakePair(token, delayMs); });
    }
};

} // namespace

void TestFirewallPolicy::testFirstConnectHeldUntilBlockConfirmed()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    // Empty rule store and the helper cannot install anything: two failures (state change, then the
    // check before connecting).
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    auto filter = helper.makeController();
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QCOMPARE(filter.wanted(), DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(!filter.isBlockConfirmed());
    QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);  // no block at all
    QVERIFY(!filter.mayConnect());                  // the connection is held
    QCOMPARE(helper.sent.size(), 2);                // it asked once more first
    QVERIFY(!helper.retries.isEmpty());             // and keeps retrying

    // The retry gets the blocks in: the next connect may go ahead.
    filter.onRetry(helper.retries.last().first);
    QVERIFY(filter.isBlockConfirmed());
    QVERIFY(filter.mayConnect());

    // Blocks in but a permit missing: blocks are what matters for connecting.
    FakeDnsLeakFilterHelper partial;
    partial.answers = {DnsLeakFilterSendResult::kIncomplete};
    auto filter2 = partial.makeController();
    filter2.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(filter2.mayConnect());
    QCOMPARE(partial.sent.size(), 1);
    QCOMPARE(partial.retries.size(), 1);  // the rest is still retried

    // Once confirmed, a later failure keeps the confirmed blocks in place (the helper keeps them).
    FakeDnsLeakFilterHelper later;
    auto filter3 = later.makeController();
    filter3.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    later.answers = {DnsLeakFilterSendResult::kFailed};
    filter3.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QVERIFY(filter3.isBlockConfirmed());
    QCOMPARE(later.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // Without a proxy nothing is held.
    FakeDnsLeakFilterHelper none;
    auto filter4 = none.makeController();
    filter4.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QVERIFY(filter4.mayConnect());
    QVERIFY(none.sent.isEmpty());
}

void TestFirewallPolicy::testStaleRetryDoesNotUndoUnproxiedSession()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    // A proxied session; at its end the helper fails to remove the filter once.
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    filter.onConnectState(CONNECT_STATE_DISCONNECTING, true, false);
    helper.answers = {DnsLeakFilterSendResult::kFailed};
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, true, false);
    QCOMPARE(filter.wanted(), DnsLeakFilter::kOff);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);  // the disable failed
    QCOMPARE(helper.retries.size(), 1);
    const quint64 staleToken = helper.retries.last().first;

    // The proxy is turned off and an ordinary OpenVPN session starts; its connector enables the filter.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    helper.inPlace = DnsLeakFilter::kBlockAll;
    const int sentBefore = helper.sent.size();

    // The old retry fires late: it must not turn the new session's filter off.
    filter.onRetry(staleToken);
    QCOMPARE(helper.sent.size(), sentBefore);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    QVERIFY(!filter.isBlockConfirmed());  // the filter is not the engine's any more

    // That session ends; its connector removes the filter.
    filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);
    filter.onConnectState(CONNECT_STATE_DISCONNECTING, false, false);
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, false);
    helper.inPlace = DnsLeakFilter::kOff;

    // The next proxied connection cannot install its rules: it must not be allowed on the old
    // confirmation.
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(!filter.mayConnect());
    QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    // Once the helper confirms, it may.
    QVERIFY(filter.mayConnect());
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
}

void TestFirewallPolicy::testReconnectNeedsNotConnectedRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(filter.mayStartAttempt());
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kBlockAll);  // connected rules in place

    // The tunnel drops. Windows rejects the reconnecting rules (local ranges, no custom DNS
    // exception): the connected rules stay, and they are not enough for an attempt.
    // (Two failures: the state change, then the check, which asks the helper once more.)
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    QVERIFY(filter.isBlockConfirmed());
    QVERIFY(!filter.mayStartAttempt());  // the connection manager's own retry is stopped
    QVERIFY(filter.mayStartAttempt());   // after the helper confirms, it goes ahead
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // The connection manager retrying before the engine has seen the reconnect (state still
    // CONNECTED, wanted still the connected rules) also gets the not-connected rules first.
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kBlockAll);
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    QVERIFY(!filter.mayStartAttempt());
    QCOMPARE(filter.wanted(), DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(filter.mayStartAttempt());

    // Sessions without a proxy are never stopped here.
    FakeDnsLeakFilterHelper none;
    auto plain = none.makeController();
    plain.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QVERIFY(plain.mayStartAttempt());
    QVERIFY(none.sent.isEmpty());
}

void TestFirewallPolicy::testRetryBacksOffAndStopsOnSuccess()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    auto filter = helper.makeController();
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QCOMPARE(helper.retries.size(), 1);
    QCOMPARE(helper.retries[0].second, ProxiedDnsLeakFilter::kFirstRetryMs);
    filter.onRetry(helper.retries[0].first);
    QCOMPARE(helper.retries.size(), 2);
    QCOMPARE(helper.retries[1].second, 2 * ProxiedDnsLeakFilter::kFirstRetryMs);

    // A newer send succeeds before the retry fires: the retry is void and nothing more is scheduled.
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    const int sentBefore = helper.sent.size();
    filter.onRetry(helper.retries[1].first);
    QCOMPARE(helper.sent.size(), sentBefore);
    QCOMPARE(helper.retries.size(), 2);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
}

QTEST_MAIN(TestFirewallPolicy)
