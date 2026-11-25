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

    void firewallOn(const QString &connectingIp, const QSet<QString> &ips, bool, bool, bool isVpnConnected) override
    {
        isOn_ = true;
        ++onCalls;
        lastConnectingIp = connectingIp;
        lastIps = ips;
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
    const QSet<QString> ips = exceptions.getIPAddressesForNotConnectedState(false);

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
    QCOMPARE(exceptions.getIPAddressesForNotConnectedState(true), exceptions.getIPAddressesForFirewallForConnectedState());
}

void TestFirewallPolicy::testNotConnectedExceptionsWithoutProxy()
{
    const FirewallExceptions exceptions = makeExceptions(false);
    QVERIFY(!exceptions.isProxySet());
    QCOMPARE(exceptions.getIPAddressesForNotConnectedState(false), exceptions.getIPAddressesForFirewall());
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
                                     [&exceptions]() { return exceptions.getIPAddressesForNotConnectedState(false); },
                                     true, true);

    QVERIFY(exceptions.connectingIp().isEmpty());
    QVERIFY(controller.firewallActualState());
    QCOMPARE(controller.offCalls, 0);
    QCOMPARE(controller.onCalls, 1);
    QVERIFY(controller.lastConnectingIp.isEmpty());
    QVERIFY(!controller.lastIsVpnConnected);
    QVERIFY(!controller.lastIps.contains("203.0.113.7"));
    QVERIFY(!controller.lastIps.contains("10.8.0.1"));
}

void TestFirewallPolicy::testLeaveConnectionLeavesFirewallOff()
{
    FirewallExceptions exceptions = makeExceptions(true);
    bool changed = false;
    exceptions.setConnectingIp("203.0.113.7", changed);

    FakeFirewallController controller(false);
    firewall_policy::leaveConnection(controller, exceptions,
                                     [&exceptions]() { return exceptions.getIPAddressesForNotConnectedState(false); },
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

QTEST_MAIN(TestFirewallPolicy)
