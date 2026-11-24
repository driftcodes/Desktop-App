#include "customconfiglocationinfo.test.h"

#include <QSignalSpy>
#include <QtTest>

#include "engine/customconfigs/wireguardcustomconfig.h"
#include "engine/locationsmodel/customconfiglocationinfo.h"
#include "engine/locationsmodel/tests/customconfigfixtures.h"
#include "types/locationid.h"

using customconfig_fixtures::makeOvpnCustomConfigLocationInfo;
using customconfig_fixtures::makeWireGuardCustomConfigLocationInfo;

namespace {

// The WG file parser can't produce a v6-literal endpoint (it splits the Endpoint value on ':'),
// so hand-roll a config that reports one to reach the v6 skip in resolveHostnamesForWireGuardConfig.
class V6EndpointWireguardConfig : public customconfigs::WireguardCustomConfig
{
public:
    QStringList hostnames() const override { return QStringList() << "2001:db8::1"; }
};

class FakeDnsResult : public wsnet::WSNetDnsRequestResult
{
public:
    explicit FakeDnsResult(std::vector<std::string> ips) : ips_(std::move(ips)) {}
    std::vector<std::string> ips() const override { return ips_; }
    std::uint32_t elapsedMs() const override { return 0; }
    std::shared_ptr<wsnet::WSNetRequestError> error() const override { return nullptr; }

private:
    std::vector<std::string> ips_;
};

} // namespace

void TestCustomConfigLocationInfo::testSelectedEndpointConfigAppendsRemoteToBody()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 443\n");
    QVERIFY(info);
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);
    info->resolveHostnames();
    // IP-literal remotes resolve synchronously.
    QCOMPARE(resolvedSpy.count(), 1);

    const QString config = info->getOvpnConfigForSelectedEndpoint();
    // The body (remote lines stripped at parse) comes first; the selected remote is re-appended
    // last with CRLF framing, exactly once.
    QVERIFY(config.contains("dev tun\n"));
    QVERIFY(config.contains("auth-user-pass\n"));
    QVERIFY(config.endsWith("remote 1.2.3.4 443\r\n"));
    QCOMPARE(config.count("remote 1.2.3.4"), 1);
}

void TestCustomConfigLocationInfo::testSelectedEndpointConfigSubstitutesResolvedIp()
{
    // Seed a resolved hostname remote directly: real resolution goes through wsnet DNS, which is
    // out of reach for a unit test.
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote vpn.example.com 443 tcp\n");
    QVERIFY(info);
    locationsmodel::CustomConfigLocationInfo::RemoteDescr rd;
    rd.ipOrHostname_ = "vpn.example.com";
    rd.isHostname = true;
    rd.isResolved = true;
    rd.ipsForHostname_ = QStringList() << "5.6.7.8";
    rd.remoteCmdLine = "remote vpn.example.com 443 tcp";
    rd.port = 443;
    rd.protocol = "tcp";
    info->remotes_ << rd;
    info->bAllResolved_ = true;

    QVERIFY(info->isExistSelectedNode());
    QCOMPARE(info->getSelectedIp(), QString("5.6.7.8"));
    QVERIFY(info->getOvpnConfigForSelectedEndpoint().endsWith("remote 5.6.7.8 443 tcp\r\n"));
}

void TestCustomConfigLocationInfo::testSelectedEndpointConfigFollowsSelectedNode()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 443\nremote 9.8.7.6 1194\n");
    QVERIFY(info);
    info->resolveHostnames();

    QVERIFY(info->getOvpnConfigForSelectedEndpoint().endsWith("remote 1.2.3.4 443\r\n"));
    info->selectNextNode();
    QVERIFY(info->getOvpnConfigForSelectedEndpoint().endsWith("remote 9.8.7.6 1194\r\n"));
}

void TestCustomConfigLocationInfo::testIsExistSelectedNodeFalseCases()
{
    // A v6-only DNS answer leaves ipsForHostname_ empty on a resolved remote; such an endpoint
    // must not be selectable, or doConnect() dials into the firewall with no useful error.
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote vpn.example.com 443 tcp\n");
    QVERIFY(info);
    locationsmodel::CustomConfigLocationInfo::RemoteDescr rd;
    rd.ipOrHostname_ = "vpn.example.com";
    rd.isHostname = true;
    rd.isResolved = true;
    rd.remoteCmdLine = "remote vpn.example.com 443 tcp";
    rd.port = 443;
    rd.protocol = "tcp";
    info->remotes_ << rd;
    info->bAllResolved_ = true;
    QVERIFY(!info->isExistSelectedNode());
    // Before resolution completes the node reports selectable by design: the connect flow
    // resolves first and only consults concrete endpoints afterwards.
    auto unresolved = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote vpn.example.com 443 tcp\n");
    QVERIFY(unresolved);
    QVERIFY(unresolved->isExistSelectedNode());
}

void TestCustomConfigLocationInfo::testResolveHostnamesReEmitsWhenAlreadyResolved()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 443\n");
    QVERIFY(info);
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);
    info->resolveHostnames();
    QCOMPARE(resolvedSpy.count(), 1);
    // A second attempt on an already-resolved location must re-emit instead of stalling the connect.
    info->resolveHostnames();
    QCOMPARE(resolvedSpy.count(), 2);
}

void TestCustomConfigLocationInfo::testSelectedPortProtocolGlobalFallback()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nport 1194\nproto tcp\nremote 1.2.3.4\n");
    QVERIFY(info);
    info->resolveHostnames();
    QCOMPARE(info->remotes_[0].port, 0u);
    QCOMPARE(info->getSelectedPort(), 1194u);
    // The parser pre-fills the per-remote protocol from the global directive, so blank it to
    // exercise getSelectedProtocol()'s own fallback branch.
    info->remotes_[0].protocol.clear();
    QCOMPARE(info->getSelectedProtocol(), QString("tcp"));
}

void TestCustomConfigLocationInfo::testOvpnV6LiteralRemoteSkipped()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 2001:db8::1 443\nremote 1.2.3.4 443\n");
    QVERIFY(info);
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);
    info->resolveHostnames();
    QCOMPARE(resolvedSpy.count(), 1);
    QCOMPARE(info->remotes_.count(), 1);
    QVERIFY(info->isExistSelectedNode());
    QCOMPARE(info->getSelectedIp(), QString("1.2.3.4"));
}

void TestCustomConfigLocationInfo::testWireGuardIpLiteralResolve()
{
    auto info = makeWireGuardCustomConfigLocationInfo("1.2.3.4:51820");
    QVERIFY(info);
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);
    info->resolveHostnames();
    QCOMPARE(resolvedSpy.count(), 1);
    QVERIFY(info->isExistSelectedNode());
    QCOMPARE(info->getSelectedIp(), QString("1.2.3.4"));
    QCOMPARE(info->getSelectedPort(), 51820u);
    QCOMPARE(info->getSelectedProtocol(), QString("WireGuard"));
}

void TestCustomConfigLocationInfo::testWireGuardV6LiteralEndpointSkipped()
{
    QSharedPointer<const customconfigs::ICustomConfig> config(new V6EndpointWireguardConfig);
    auto info = QSharedPointer<locationsmodel::CustomConfigLocationInfo>::create(
        LocationID::createCustomConfigLocationId(config->filename()), config);
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);
    info->resolveHostnames();
    QCOMPARE(resolvedSpy.count(), 1);
    QVERIFY(!info->isExistSelectedNode());
}

void TestCustomConfigLocationInfo::testHostnameMultiIpRotation()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote vpn.example.com 443 tcp\n");
    QVERIFY(info);
    locationsmodel::CustomConfigLocationInfo::RemoteDescr rd;
    rd.ipOrHostname_ = "vpn.example.com";
    rd.isHostname = true;
    rd.isResolved = true;
    rd.ipsForHostname_ = QStringList() << "10.0.0.1" << "10.0.0.2" << "10.0.0.3";
    rd.remoteCmdLine = "remote vpn.example.com 443 tcp";
    rd.port = 443;
    rd.protocol = "tcp";
    info->remotes_ << rd;
    info->bAllResolved_ = true;
    QCOMPARE(info->getSelectedIp(), QString("10.0.0.1"));
    info->selectNextNode();
    QCOMPARE(info->getSelectedIp(), QString("10.0.0.2"));
    info->selectNextNode();
    QCOMPARE(info->getSelectedIp(), QString("10.0.0.3"));
    // Past the last resolved ip a single remote wraps back to its first ip.
    info->selectNextNode();
    QCOMPARE(info->getSelectedIp(), QString("10.0.0.1"));
}

void TestCustomConfigLocationInfo::testSelectNodeWithProtocolSkipsUdpRemotes()
{
    // Mixed profile: under a proxy only the TCP remote may be dialed.
    auto info = makeOvpnCustomConfigLocationInfo(
        "dev tun\nauth-user-pass\nremote 1.2.3.4 1194 udp\nremote 9.8.7.6 443 tcp\nremote 5.5.5.5 1195 udp\n");
    QVERIFY(info);
    info->resolveHostnames();

    QCOMPARE(info->getSelectedProtocol(), QString("udp"));
    QVERIFY(info->selectNodeWithProtocol("tcp"));
    QCOMPARE(info->getSelectedIp(), QString("9.8.7.6"));
    QCOMPARE(info->getSelectedProtocol(), QString("tcp"));

    // Already on a TCP node: the selection stays put.
    QVERIFY(info->selectNodeWithProtocol("TCP"));
    QCOMPARE(info->getSelectedIp(), QString("9.8.7.6"));

    // After a failure the walk advances, skips the UDP remotes and wraps back to the TCP one.
    info->selectNextNode();
    QVERIFY(info->selectNodeWithProtocol("tcp"));
    QCOMPARE(info->getSelectedIp(), QString("9.8.7.6"));
}

void TestCustomConfigLocationInfo::testSelectNodeWithProtocolNoMatchKeepsSelection()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 1194 udp\nremote 9.8.7.6 1195 udp\n");
    QVERIFY(info);
    info->resolveHostnames();
    info->selectNextNode();
    QCOMPARE(info->getSelectedIp(), QString("9.8.7.6"));

    QVERIFY(!info->selectNodeWithProtocol("tcp"));
    QCOMPARE(info->getSelectedIp(), QString("9.8.7.6"));
    QCOMPARE(info->getSelectedProtocol(), QString("udp"));
}

void TestCustomConfigLocationInfo::testSharedHostnameResolvesEveryRemote()
{
    // A common provider layout: one hostname, a UDP and a TCP remote. Seeded as resolveHostnames()
    // leaves it while the lookups are in flight.
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote vpn.example.com 1194 udp\n");
    QVERIFY(info);
    auto unresolvedRemote = [](const QString &hostname, uint port, const QString &protocol) {
        locationsmodel::CustomConfigLocationInfo::RemoteDescr rd;
        rd.ipOrHostname_ = hostname;
        rd.isHostname = true;
        rd.isResolved = false;
        rd.remoteCmdLine = QString("remote %1 %2 %3").arg(hostname).arg(port).arg(protocol);
        rd.port = port;
        rd.protocol = protocol;
        return rd;
    };
    info->remotes_ << unresolvedRemote("vpn.example.com", 1194, "udp") << unresolvedRemote("vpn.example.com", 443, "tcp");
    QSignalSpy resolvedSpy(info.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved);

    info->onDnsRequestFinished("vpn.example.com", std::make_shared<FakeDnsResult>(std::vector<std::string>{"5.6.7.8"}));

    // One answer resolves both remotes, so the attempt can proceed (it used to hang here).
    QCOMPARE(resolvedSpy.count(), 1);
    // A second answer for the same name (a duplicate lookup) must not start the attempt again.
    info->onDnsRequestFinished("vpn.example.com", std::make_shared<FakeDnsResult>(std::vector<std::string>{"5.6.7.8"}));
    QCOMPARE(resolvedSpy.count(), 1);
    QVERIFY(info->remotes_[0].isResolved);
    QVERIFY(info->remotes_[1].isResolved);
    QCOMPARE(info->remotes_[1].ipsForHostname_, QStringList() << "5.6.7.8");
    QVERIFY(info->selectNodeWithProtocol("tcp"));
    QCOMPARE(info->getSelectedPort(), 443u);
    QVERIFY(info->getOvpnConfigForSelectedEndpoint().endsWith("remote 5.6.7.8 443 tcp\r\n"));
}

void TestCustomConfigLocationInfo::testResolveOnlyProtocolKeepsMatchingRemotes()
{
    auto info = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 1194 udp\nremote 5.6.7.8 443 tcp\n");
    QVERIFY(info);
    QVERIFY(info->hasRemoteWithProtocol("tcp"));
    QVERIFY(info->hasRemoteWithProtocol("UDP"));
    info->resolveHostnames("tcp");
    QCOMPARE(info->remotes_.count(), 1);
    QCOMPARE(info->getSelectedIp(), QString("5.6.7.8"));
    QCOMPARE(info->getSelectedProtocol(), QString("tcp"));

    auto udpOnly = makeOvpnCustomConfigLocationInfo("dev tun\nauth-user-pass\nremote 1.2.3.4 1194 udp\n");
    QVERIFY(udpOnly);
    QVERIFY(!udpOnly->hasRemoteWithProtocol("tcp"));
}

QTEST_MAIN(TestCustomConfigLocationInfo)
