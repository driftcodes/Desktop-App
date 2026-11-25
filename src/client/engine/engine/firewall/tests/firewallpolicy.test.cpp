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
    // Connect, drop (Wi-Fi or Throne), reconnect, then the user's disconnect. The filter must never
    // be off in between, also where the old OpenVPN process has exited and the next not started.
    const CONNECT_STATE sequence[] = {CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED,
                                      CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTING,  // next attempt
                                      CONNECT_STATE_CONNECTED,  CONNECT_STATE_DISCONNECTING,
                                      CONNECT_STATE_CONNECTING, CONNECT_STATE_CONNECTED,   // location change
                                      CONNECT_STATE_DISCONNECTING};
    const DnsLeakFilter expected[] = {DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kBlockAll,
                                      DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kPermitWindscribeApps,
                                      DnsLeakFilter::kBlockAll,             DnsLeakFilter::kPermitWindscribeApps,
                                      DnsLeakFilter::kPermitWindscribeApps, DnsLeakFilter::kBlockAll,
                                      DnsLeakFilter::kPermitWindscribeApps};
    DnsLeakFilter filter = DnsLeakFilter::kOff;
    for (size_t i = 0; i < sizeof(sequence) / sizeof(sequence[0]); ++i) {
        // The proxy being turned off mid-session does not drop the filter either.
        const auto step = proxiedDnsLeakFilter(filter, sequence[i], i < 4);
        filter = step.next;
        QCOMPARE(filter, expected[i]);
        if (sequence[i] == CONNECT_STATE_CONNECTING) {
            QVERIFY(step.apply);  // re-applied per attempt, for the current network's DNS servers
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

QTEST_MAIN(TestFirewallPolicy)
