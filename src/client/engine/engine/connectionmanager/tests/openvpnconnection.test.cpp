#include <QSignalSpy>
#include <QTcpServer>
#include <QtTest>

#include "openvpnconnection.test.h"

#include <memory>

#include "api_responses/servercredentials.h"
#include "engine/connectionmanager/connectors/openvpn/makeovpnfile.h"
#include "engine/connectionmanager/connectors/openvpn/openvpnconnection.h"
#include "engine/customconfigs/ovpnroutingpolicy.h"
#include "extraconfig_mock.h"
#include "fakes.h"
#include "types/enums.h"
#include "utils/log/logger.h"

namespace {

api_responses::ServerCredentials makeCredentials(const QString &username, const QString &password)
{
    const QString json = QString("{\"data\":{\"username\":\"%1\",\"password\":\"%2\"}}")
                             .arg(QString(username.toUtf8().toBase64()), QString(password.toUtf8().toBase64()));
    return api_responses::ServerCredentials(json.toStdString());
}

OpenVpnSessionParams makeSessionParams()
{
    OpenVpnSessionParams params;
    params.ovpnConfig = "dev tun";
    params.serverCredentials = makeCredentials("session-user", "session-pass");
    return params;
}

CurrentConnectionDescr makeUdpDescr()
{
    CurrentConnectionDescr d;
    d.connectionNodeType = CONNECTION_NODE_DEFAULT;
    d.protocol = types::Protocol::OPENVPN_UDP;
    d.ip = "10.1.2.3";
    d.hostname = "ovpn.example.com";
    d.port = 443;
    d.verifyX509name = "x509.example.com";
    return d;
}

} // namespace

void TestOpenVPNConnection::initTestCase()
{
    QCoreApplication::setOrganizationName("WindscribeTest");
    QCoreApplication::setApplicationName("openvpnconnection.test");
    qRegisterMetaType<ConnectError>("ConnectError");
}

void TestOpenVPNConnection::init()
{
    helper_ = new Helper(std::unique_ptr<IHelperBackend>(new FakeHelperBackend()),
                         log_utils::Logger::instance().getSpdLogger("basic"));
    ExtraConfigMock::reset();
}

void TestOpenVPNConnection::cleanup()
{
    delete helper_;
    helper_ = nullptr;
}

AttemptEnvironment TestOpenVPNConnection::makeEnv()
{
    AttemptEnvironment env;
    env.packetSize.isAutomatic = true;
    env.defaultAdapterInfo.setAdapterName("fake0");
    env.defaultAdapterInfo.addGatewayIp(types::IpAddress("192.168.1.1"));
    env.primaryDnsServer = "10.255.255.2";
    return env;
}

void TestOpenVPNConnection::testPrepareUdpUsesSessionCredentials()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    QSignalSpy failedSpy(&conn, &IConnection::prepareFailed);

    conn.prepare(makeUdpDescr(), makeEnv());

    QCOMPARE(preparedSpy.count(), 1);
    QCOMPARE(failedSpy.count(), 0);
    QVERIFY(conn.config_.startsWith("dev tun"));
    QVERIFY(conn.config_.contains("remote 10.1.2.3"));
    QVERIFY(conn.config_.contains("port 443"));
    QVERIFY(conn.config_.contains("proto udp"));
    QVERIFY(conn.config_.contains("verify-x509-name x509.example.com name"));
    QVERIFY(conn.config_.contains("dhcp-option DNS 10.255.255.2"));
    // Automatic packet size: no explicit MSS clamp.
    QVERIFY(!conn.config_.contains("mssfix"));
    QCOMPARE(conn.username_, QString("session-user"));
    QCOMPARE(conn.password_, QString("session-pass"));
    QVERIFY(!conn.isCustomConfig_);
}

void TestOpenVPNConnection::testPrepareRefinesProtocolToDialedVariant()
{
    // A connector built with the pre-resolve family representative (emergency, custom) takes the
    // attempt's dialed variant at prepare().
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);

    CurrentConnectionDescr descr = makeUdpDescr();
    descr.protocol = types::Protocol::OPENVPN_TCP;
    conn.prepare(descr, makeEnv());

    QCOMPARE(preparedSpy.count(), 1);
    QCOMPARE(conn.protocol_, types::Protocol::OPENVPN_TCP);
    QVERIFY(conn.config_.contains("proto tcp-client"));
}

void TestOpenVPNConnection::testPrepareStaticIpUsesDescrCredentials()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    CurrentConnectionDescr descr = makeUdpDescr();
    descr.connectionNodeType = CONNECTION_NODE_STATIC_IPS;
    descr.staticIps.credentials = api_responses::ServerCredentials("static-user", "static-pass");

    conn.prepare(descr, makeEnv());

    QCOMPARE(conn.username_, QString("static-user"));
    QCOMPARE(conn.password_, QString("static-pass"));
}

void TestOpenVPNConnection::testPrepareManualPacketSizeAddsMss()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    AttemptEnvironment env = makeEnv();
    env.packetSize.isAutomatic = false;
    env.packetSize.mtu = 1500;

    conn.prepare(makeUdpDescr(), env);

    // Default OpenVPN MTU offset is 40.
    QVERIFY(conn.config_.contains("mssfix 1460"));
}

void TestOpenVPNConnection::testPrepareManualPacketSizeHonorsExtraConfigOffset()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    ExtraConfigMock::hasMtuOffsetOpenVpn = true;
    ExtraConfigMock::mtuOffsetOpenVpn = 100;
    AttemptEnvironment env = makeEnv();
    env.packetSize.isAutomatic = false;
    env.packetSize.mtu = 1500;

    conn.prepare(makeUdpDescr(), env);

    QVERIFY(conn.config_.contains("mssfix 1400"));
}

void TestOpenVPNConnection::testPrepareMssTooLowOmitsMssfix()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    AttemptEnvironment env = makeEnv();
    env.packetSize.isAutomatic = false;
    env.packetSize.mtu = 30;

    conn.prepare(makeUdpDescr(), env);

    QVERIFY(!conn.config_.contains("mssfix"));
}

void TestOpenVPNConnection::testPrepareAntiCensorshipAddsStuffing()
{
    // The emergency session carries the user's anti-censorship setting without an amnezia preset.
    OpenVpnSessionParams params = makeSessionParams();
    params.isAntiCensorship = true;
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, params);

    conn.prepare(makeUdpDescr(), makeEnv());

    QVERIFY(conn.config_.contains("udp-stuffing"));
    QVERIFY(conn.config_.contains("tcp-split-reset"));
}

void TestOpenVPNConnection::testPrepareCustomConfigInjectsDnsAndClearsCredentials()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    CurrentConnectionDescr descr;
    descr.connectionNodeType = CONNECTION_NODE_CUSTOM_CONFIG;
    descr.protocol = types::Protocol::OPENVPN_UDP;
    descr.ip = "5.6.7.8";
    // The descriptor carries the finished .ovpn text, assembled upstream with the resolved node ip.
    descr.openVpn.customConfig = "dev tun\r\nauth-user-pass\r\nremote 5.6.7.8 443\r\n";

    conn.prepare(descr, makeEnv());

    QCOMPARE(preparedSpy.count(), 1);
    QVERIFY(conn.config_.contains("remote 5.6.7.8 443"));
    // The override is a pair: the pull-filter drops the server-pushed DNS, the dhcp-option sets ours.
    QVERIFY(conn.config_.contains("pull-filter ignore \"dhcp-option DNS\""));
    QVERIFY(conn.config_.contains("dhcp-option DNS 10.255.255.2"));
    QVERIFY(conn.isCustomConfig_);
    // Custom-config credentials arrive via the user-input path, never from the session.
    QVERIFY(conn.username_.isEmpty());
    QVERIFY(conn.password_.isEmpty());
}

void TestOpenVPNConnection::testRunOpenVpnCustomConfigDetailEmitsCustomConfigInvalid()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    conn.isCustomConfig_ = true;
    conn.connectErrorDetail_ = "Windscribe: directive not permitted in config: up (config.ovpn:12)";

    QCOMPARE(conn.launchFailureError(), ConnectError::kCustomConfigInvalid);
    QCOMPARE(conn.takeConnectErrorDetail(), QString("Windscribe: directive not permitted in config: up (config.ovpn:12)"));
    // Consumed once, so a later error cannot reuse the line.
    QVERIFY(conn.takeConnectErrorDetail().isEmpty());
    // The detail is gone, so a repeat of the same failure is a plain launch failure.
    QCOMPARE(conn.launchFailureError(), ConnectError::kLocalProcessLaunchFailure);
}

void TestOpenVPNConnection::testRunOpenVpnEmptyDetailEmitsLaunchFailure()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    conn.isCustomConfig_ = true;
    QCOMPARE(conn.launchFailureError(), ConnectError::kLocalProcessLaunchFailure);

    // An official config keeps the launch-failure code even when the daemon left a fatal line.
    // The custom-config dialog switches the selected location, which must not happen here.
    conn.isCustomConfig_ = false;
    conn.connectErrorDetail_ = "Windscribe: directive not permitted in config: up (config.ovpn:12)";
    QCOMPARE(conn.launchFailureError(), ConnectError::kLocalProcessLaunchFailure);
}

void TestOpenVPNConnection::testPrepareInvalidNodeIpFails()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    QSignalSpy failedSpy(&conn, &IConnection::prepareFailed);
    CurrentConnectionDescr descr = makeUdpDescr();
    descr.ip = "not-an-ip";

    conn.prepare(descr, makeEnv());

    QCOMPARE(preparedSpy.count(), 0);
    QCOMPARE(failedSpy.count(), 1);
    QCOMPARE(qvariant_cast<ConnectError>(failedSpy.at(0).at(0)), ConnectError::kLocalProcessLaunchFailure);
}

void TestOpenVPNConnection::testParsePushReplyRedirectGateway()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    const QString reply = ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,"
                          "route-gateway 10.255.255.1,topology subnet,ping 10,ping-restart 60,"
                          "ifconfig 10.255.255.6 255.255.255.0,dhcp-option DNS 10.255.255.3,dhcp-option DNS 10.255.255.4,peer-id 0'";
    AdapterGatewayInfo info;
    bool redirect = false;

    QVERIFY(conn.parsePushReply(reply, info, redirect));

    QVERIFY(redirect);
    QCOMPARE(QString::fromStdString(info.adapterIpV4().toString()), QString("10.255.255.6"));
    QCOMPARE(QString::fromStdString(info.gatewayV4().toString()), QString("10.255.255.1"));
    QCOMPARE(info.dnsServersAsStringList(), QStringList({"10.255.255.3", "10.255.255.4"}));
}

void TestOpenVPNConnection::testParsePushReplyNoRedirectGateway()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    const QString reply = ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.255.255.1,"
                          "ifconfig 10.255.255.6 255.255.255.0,dhcp-option DNS 10.255.255.3'";
    AdapterGatewayInfo info;
    bool redirect = true;

    QVERIFY(conn.parsePushReply(reply, info, redirect));

    QVERIFY(!redirect);
    QCOMPARE(QString::fromStdString(info.adapterIpV4().toString()), QString("10.255.255.6"));

    // An IPv6-only redirect does not redirect IPv4; a plain redirect-gateway (no def1) does.
    QVERIFY(conn.parsePushReply(">LOG:1,,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1 ipv6 !ipv4,"
                                "ifconfig 10.255.255.6 255.255.255.0'", info, redirect));
    QVERIFY(!redirect);
    QVERIFY(conn.parsePushReply(">LOG:1,,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway,"
                                "ifconfig 10.255.255.6 255.255.255.0'", info, redirect));
    QVERIFY(redirect);
}

void TestOpenVPNConnection::testParsePushReplyIpv6Options()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    // Verbatim from a user report: ifconfig-ipv6 precedes the IPv4 ifconfig, and redirect-gateway
    // appears twice.
    const QString reply = ">LOG:1788931456,,PUSH: Received control message: 'PUSH_REPLY,"
                          "dhcp-option DNS 192.168.101.1,route-ipv6 2000::/3,"
                          "redirect-gateway def1 bypass-dhcp,redirect-gateway ipv6,tun-ipv6,"
                          "route-gateway 192.168.101.1,topology subnet,ping 35,ping-restart 180,"
                          "ifconfig-ipv6 2002:5fd7:2da8:1::29/112 2002:5fd7:2da8:1::1,"
                          "ifconfig 192.168.101.41 255.255.255.0,peer-id 1,cipher CHACHA20-POLY1305'";
    AdapterGatewayInfo info;
    bool redirect = false;

    QVERIFY(conn.parsePushReply(reply, info, redirect));

    QVERIFY(redirect);
    QCOMPARE(QString::fromStdString(info.adapterIpV4().toString()), QString("192.168.101.41"));
    QCOMPARE(QString::fromStdString(info.gatewayV4().toString()), QString("192.168.101.1"));
    QCOMPARE(info.dnsServersAsStringList(), QStringList({"192.168.101.1"}));
}

void TestOpenVPNConnection::testParsePushReplyMalformed()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    const QStringList malformed = {
        // No quoted payload.
        ">LOG:1602589553,,PUSH: Received control message: PUSH_REPLY,route-gateway 10.255.255.1",
        // route-gateway missing its address.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,route-gateway'",
        // route-gateway with a non-IP address.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,route-gateway not-an-ip'",
        // ifconfig missing the netmask.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.255.255.6'",
        // ifconfig with a non-IP address.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,ifconfig not-an-ip 255.255.255.0'",
        // dhcp-option DNS with a non-IP address.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS not-an-ip'",
        // dhcp-option truncated.
        ">LOG:1602589553,,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS'",
    };

    for (const QString &reply : malformed) {
        AdapterGatewayInfo info;
        bool redirect = true;
        QVERIFY2(!conn.parsePushReply(reply, info, redirect), qPrintable(reply));
    }
}

void TestOpenVPNConnection::testParseDeviceOpenedReply()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    struct Row {
        QString reply;
        QString device;
    };
    const QVector<Row> rows = {
        // mac utun form.
        {">LOG:1602589552,,Opened utun device utun3", "utun3"},
        // mac capital-D variant.
        {">LOG:1602589552,,Opened utun Device utun5", "utun5"},
        // linux tun/tap form.
        {">LOG:1602589552,I,TUN/TAP device tun0 opened", "tun0"},
        // linux DCO form.
        {">LOG:1602589552,I,DCO device tun0 opened", "tun0"},
    };

    for (const Row &row : rows) {
        QString device;
        QVERIFY2(conn.parseDeviceOpenedReply(row.reply, device), qPrintable(row.reply));
        QCOMPARE(device, row.device);
    }
}

void TestOpenVPNConnection::testParseDeviceOpenedReplyMalformed()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    const QStringList malformed = {
        // Fewer than three comma fields.
        ">LOG:1602589552,Opened utun device utun3",
        // No 'device' keyword.
        ">LOG:1602589552,,Opened utun utun3",
        // 'device' is the last word.
        ">LOG:1602589552,,Opened utun device",
    };

    for (const QString &reply : malformed) {
        QString device;
        QVERIFY2(!conn.parseDeviceOpenedReply(reply, device), qPrintable(reply));
    }
}

void TestOpenVPNConnection::testParseConnectedSuccessReply()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QString remoteIp;

    QVERIFY(conn.parseConnectedSuccessReply(">STATE:1602589554,CONNECTED,SUCCESS,10.255.255.6,185.204.1.174,1194,,", remoteIp));

    QCOMPARE(remoteIp, QString("185.204.1.174"));
}

void TestOpenVPNConnection::testParseConnectedSuccessReplyMalformed()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    const QStringList malformed = {
        // Fewer than five comma fields.
        ">STATE:1602589554,CONNECTED,SUCCESS,10.255.255.6",
        // Remote ip field present but empty.
        ">STATE:1602589554,CONNECTED,SUCCESS,10.255.255.6,,1194",
    };

    for (const QString &reply : malformed) {
        QString remoteIp;
        QVERIFY2(!conn.parseConnectedSuccessReply(reply, remoteIp), qPrintable(reply));
    }
}

void TestOpenVPNConnection::testSanitizeString()
{
    // Credentials are embedded in a quoted management command: CR/LF would inject a second command,
    // so they are stripped; backslash, quote and tab are escaped per management-notes.txt.
    struct Row {
        QString in;
        QString out;
    };
    const QVector<Row> rows = {
        {"plain-pass", "plain-pass"},
        {"pa\"ss", "pa\\\"ss"},
        {"a\\b", "a\\\\b"},
        {"a\tb", "a\\tb"},
        {"a\rb\nc", "abc"},
        // Backslash is escaped before the quote so the pair stays two escapes, not a re-escape.
        {"\\\"", "\\\\\\\""},
        {"user\nsignal SIGTERM\n", "usersignal SIGTERM"},
    };

    for (const Row &row : rows) {
        QCOMPARE(OpenVPNConnection::sanitizeString(row.in), row.out);
    }
}

void TestOpenVPNConnection::testRedactManagementLine()
{
    struct Row {
        QString in;
        QString out;
    };
    const QVector<Row> rows = {
        {">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"xq7example-user1\"'",
         ">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"xq***\"'"},
        {">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"a\\\"b\\\\c\"'",
         ">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"a\\***\"'"},
        {">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"\"'",
         ">LOG:1792769252,D,MANAGEMENT: CMD 'username \"Auth\" \"\"'"},
        {">LOG:1792769252,D,MANAGEMENT: CMD 'password [...]'", ">LOG:1792769252,D,MANAGEMENT: CMD 'password [...]'"},
        {">LOG:1792769252,D,MANAGEMENT: CMD 'username \"HTTP Proxy\" \"proxyuser\"'",
         ">LOG:1792769252,D,MANAGEMENT: CMD 'username \"HTTP Proxy\" \"proxyuser\"'"},
        {">PASSWORD:Need 'Auth' username/password", ">PASSWORD:Need 'Auth' username/password"},
    };
    for (const auto &row : rows) {
        QCOMPARE(OpenVPNConnection::redactManagementLine(row.in), row.out);
    }
}

void TestOpenVPNConnection::testMakeOvpnFileStunnelUsesLocalWrapper()
{
    for (types::Protocol protocol : {types::Protocol::STUNNEL, types::Protocol::WSTUNNEL}) {
        MakeOVPNFile file;
        QVERIFY(file.generate("dev tun", "10.1.2.3", protocol, 443, 15501, 0, "192.168.1.1", "", "", false, ""));

        const QString config = file.config();
        QVERIFY(config.contains("remote 127.0.0.1"));
        QVERIFY(config.contains("port 15501"));
        QVERIFY(config.contains("proto tcp-client"));
        QVERIFY(!config.contains("remote 10.1.2.3"));
#if defined(Q_OS_MACOS) || defined(Q_OS_LINUX)
        // The wrapper dials the node itself; the direct host route keeps that traffic off the tunnel.
        QVERIFY(config.contains("route 10.1.2.3 255.255.255.255 192.168.1.1"));
#endif
    }
}

void TestOpenVPNConnection::testMakeOvpnFileRemoteIpSuppression()
{
    // When the advanced params carry their own remote, the generated config must not add one; the
    // override line itself comes from the extra-config text (empty in the mock), so none appears.
    ExtraConfigMock::remoteIp = "104.20.20.20";
    MakeOVPNFile file;

    QVERIFY(file.generate("dev tun", "10.1.2.3", types::Protocol::OPENVPN_UDP, 443, 0, 0, "", "", "", false, ""));

    QVERIFY(!file.config().contains("remote "));
    QVERIFY(file.config().contains("port 443"));
    QVERIFY(file.config().contains("proto udp"));

    // With the override remote carried in the extra-config text, that remote is the only one emitted.
    ExtraConfigMock::extraConfigForOpenVpn = "remote 104.20.20.20\r\n";
    MakeOVPNFile overrideFile;
    QVERIFY(overrideFile.generate("dev tun", "10.1.2.3", types::Protocol::OPENVPN_UDP, 443, 0, 0, "", "", "", false, ""));
    QVERIFY(!overrideFile.config().contains("remote 10.1.2.3"));
    QVERIFY(overrideFile.config().contains("remote 104.20.20.20"));
}

void TestOpenVPNConnection::testMakeOvpnFileExtraConfigAppend()
{
    ExtraConfigMock::extraConfigForOpenVpn = "verb 4\r\n";
    MakeOVPNFile file;

    QVERIFY(file.generate("dev tun", "10.1.2.3", types::Protocol::OPENVPN_UDP, 443, 0, 0, "", "", "", false, ""));

    QVERIFY(file.config().contains("verb 4"));
}

void TestOpenVPNConnection::testMakeOvpnFileTcpBranch()
{
    MakeOVPNFile file;

    QVERIFY(file.generate("dev tun", "10.1.2.3", types::Protocol::OPENVPN_TCP, 443, 0, 1460, "", "", "", false, ""));

    const QString config = file.config();
    QVERIFY(config.contains("remote 10.1.2.3"));
    QVERIFY(config.contains("port 443"));
    QVERIFY(config.contains("proto tcp-client"));
    // TCP handles segmentation itself; the MSS clamp is a UDP-only directive.
    QVERIFY(!config.contains("mssfix"));
}

void TestOpenVPNConnection::testMakeOvpnFileStunnelNoGatewayNoRoute()
{
    MakeOVPNFile file;

    QVERIFY(file.generate("dev tun", "10.1.2.3", types::Protocol::STUNNEL, 443, 15501, 0, "", "", "", false, ""));

    QVERIFY(file.config().contains("remote 127.0.0.1"));
    QVERIFY(!file.config().contains("route "));
}

void TestOpenVPNConnection::testPrepareCustomConfigEmptyDnsNoInjection()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    CurrentConnectionDescr descr;
    descr.connectionNodeType = CONNECTION_NODE_CUSTOM_CONFIG;
    descr.protocol = types::Protocol::OPENVPN_UDP;
    descr.ip = "5.6.7.8";
    descr.openVpn.customConfig = "dev tun\r\nauth-user-pass\r\nremote 5.6.7.8 443\r\n";
    AttemptEnvironment env = makeEnv();
    env.primaryDnsServer = "";

    conn.prepare(descr, env);

    QCOMPARE(preparedSpy.count(), 1);
    // No connected-DNS override: the custom config is used verbatim, its own DNS untouched.
    QCOMPARE(conn.config_, descr.openVpn.customConfig);
    QVERIFY(!conn.config_.contains("pull-filter"));
    QVERIFY(!conn.config_.contains("dhcp-option DNS"));
}

void TestOpenVPNConnection::testOpenVpnCapabilities()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    QCOMPARE(conn.capabilities().connectTimeoutMs, 30 * 1000);
    QVERIFY(!conn.capabilities().supportsCachedConfig);
    QVERIFY(conn.capabilities().needsSystemDnsRestore);
}

namespace {

OpenVpnSessionParams makeProxySessionParams(quint16 port)
{
    OpenVpnSessionParams params = makeSessionParams();
    params.proxySettings = types::ProxySettings(PROXY_OPTION_HTTP, "127.0.0.1", port, "", "");
    return params;
}

CurrentConnectionDescr makeCustomDescr(types::Protocol::TYPE protocol, const QString &body)
{
    CurrentConnectionDescr descr;
    descr.connectionNodeType = CONNECTION_NODE_CUSTOM_CONFIG;
    descr.protocol = protocol;
    descr.ip = "5.6.7.8";
    descr.openVpn.customConfig = body;
    return descr;
}

} // namespace

void TestOpenVPNConnection::testFirewallStaysOnWithLocalPrivateRoute()
{
    // The value the engine reads after connecting (ConnectionManager forwards it for custom configs):
    // a full-tunnel profile that routes 10.0.0.0/8 locally keeps the automatic firewall.
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    conn.prepare(makeCustomDescr(types::Protocol::OPENVPN_UDP,
                                 "dev tun\r\nredirect-gateway def1\r\nroute 10.0.0.0 255.0.0.0 net_gateway\r\n"
                                 "remote 5.6.7.8 1194 udp\r\n"),
                 makeEnv());
    QVERIFY(conn.isAllowFirewallAfterConnectionRuntime());

    // A public range routed locally is traffic the firewall would block, so it is not a full tunnel.
    OpenVPNConnection publicHole(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeSessionParams());
    publicHole.prepare(makeCustomDescr(types::Protocol::OPENVPN_UDP,
                                       "dev tun\r\nredirect-gateway def1\r\nroute 203.0.113.0 255.255.255.0 net_gateway\r\n"
                                       "remote 5.6.7.8 1194 udp\r\n"),
                       makeEnv());
    QVERIFY(!publicHole.isAllowFirewallAfterConnectionRuntime());
}

void TestOpenVPNConnection::testLoopbackProxyRouteFixKeepsRoutingPolicy()
{
    // The route fix itself is "--redirect-private local" on the helper's command line (the patched
    // OpenVPN rejects redirect-private in a config file). The engine never adds lines to the config.
    const QStringList bodies = {
        "client\r\nroute 10.20.0.0 255.255.0.0\r\nremote 5.6.7.8 443 tcp\r\n",
        "client\r\nredirect-gateway ipv6 !ipv4\r\nremote 5.6.7.8 443 tcp\r\n",
        "client\r\nredirect-gateway def1 bypass-dhcp\r\n<ca>\r\nkey data\r\n</ca>\r\nremote 5.6.7.8 443 tcp\r\n",
    };
    for (const QString &body : bodies) {
        QString config = body;
        MakeOVPNFile::removeAutolocalForLoopbackProxy(config);
        QCOMPARE(config, body);
    }
}

void TestOpenVPNConnection::testLoopbackProxyRouteFixDropsAutolocal()
{
    QString config = "client\r\nredirect-gateway def1 autolocal\r\nremote 5.6.7.8 443 tcp\r\n";
    MakeOVPNFile::removeAutolocalForLoopbackProxy(config);
    QCOMPARE(config, QString("client\r\nredirect-gateway def1\r\nremote 5.6.7.8 443 tcp\r\n"));
}

void TestOpenVPNConnection::testFirewallAfterConnectionFollowsConfigRouting()
{
    using customconfigs::analyzeOvpnRouting;
    const QStringList noPush;
    const QStringList pushDef1 = {"redirect-gateway def1 bypass-dhcp"};

    // Pushed redirect only, as with most providers; plain redirect-gateway (no def1) counts too.
    QVERIFY(analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel({"redirect-gateway"}));
    QVERIFY(!analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel(noPush));
    // "!ipv4" in a push turns IPv4 redirection off, even after an earlier redirect.
    QVERIFY(!analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel({"redirect-gateway def1 ipv6 !ipv4"}));
    QVERIFY(!analyzeOvpnRouting("redirect-gateway def1\n").sendsAllIpv4ThroughTunnel({"redirect-gateway ipv6 !ipv4"}));
    // A second, IPv6-only push adds IPv6 but keeps IPv4.
    QVERIFY(analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel({"redirect-gateway def1", "redirect-gateway ipv6"}));

    // The config's own redirect-gateway counts even when the server pushes none.
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(!analyzeOvpnRouting("redirect-gateway ipv6 !ipv4\n").sendsAllIpv4ThroughTunnel(noPush));

    // The earlier manual workaround: pushed redirect ignored, both halves routed into the tunnel.
    const QString workaround = "pull-filter ignore redirect-gateway\nroute 0.0.0.0 128.0.0.0 vpn_gateway\n"
                               "route 128.0.0.0 128.0.0.0 vpn_gateway\n";
    QVERIFY(analyzeOvpnRouting(workaround).sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(analyzeOvpnRouting(workaround).sendsAllIpv4ThroughTunnel(noPush));
    // "default" as the gateway means the VPN gateway too.
    QVERIFY(analyzeOvpnRouting("route 0.0.0.0 128.0.0.0 default\nroute 128.0.0.0 128.0.0.0 default\n").sendsAllIpv4ThroughTunnel(noPush));
    // The profile ignores pushed redirect-gateway, but the server pushes both halves as routes, which
    // the filter lets through: a full tunnel.
    QVERIFY(analyzeOvpnRouting("pull-filter ignore redirect-gateway\n")
                .sendsAllIpv4ThroughTunnel({"redirect-gateway def1", "route 0.0.0.0 128.0.0.0 vpn_gateway",
                                            "route 128.0.0.0 128.0.0.0 vpn_gateway"}));
    // Only one half, or the halves via the physical gateway, is not a full tunnel.
    QVERIFY(!analyzeOvpnRouting("route-nopull\nroute 0.0.0.0 128.0.0.0\n").sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(!analyzeOvpnRouting("route-nopull\nroute 0.0.0.0 128.0.0.0 net_gateway\nroute 128.0.0.0 128.0.0.0 net_gateway\n")
                 .sendsAllIpv4ThroughTunnel(pushDef1));
    // Pushed halves count, unless route-nopull drops them.
    const QStringList pushedHalves = {"route 0.0.0.0 128.0.0.0", "route 128.0.0.0 128.0.0.0"};
    QVERIFY(analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel(pushedHalves));
    QVERIFY(!analyzeOvpnRouting("route-nopull\n").sendsAllIpv4ThroughTunnel(pushedHalves));

    // pull-filter is a case-sensitive prefix match on the pushed line, quotes grouping one pattern:
    // ignoring "redirect-gateway ipv6" leaves a pushed "redirect-gateway def1" in place.
    QVERIFY(analyzeOvpnRouting("pull-filter ignore \"redirect-gateway ipv6\"\n").sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(!analyzeOvpnRouting("pull-filter ignore \"redirect-gateway ipv6\"\n")
                 .sendsAllIpv4ThroughTunnel({"redirect-gateway ipv6 def1"}));
    QVERIFY(!analyzeOvpnRouting("pull-filter ignore redirect\n").sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(analyzeOvpnRouting("pull-filter ignore Redirect-gateway\n").sendsAllIpv4ThroughTunnel(pushDef1));
    // The first matching rule wins.
    QVERIFY(analyzeOvpnRouting("pull-filter accept redirect-gateway\npull-filter ignore redirect-gateway\n")
                .sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(!analyzeOvpnRouting("pull-filter ignore redirect-gateway\npull-filter accept redirect-gateway\n")
                 .sendsAllIpv4ThroughTunnel(pushDef1));
    // A filter on "redirect-gateway def1" leaves a plain "redirect-gateway" push in place.
    QVERIFY(analyzeOvpnRouting("pull-filter ignore \"redirect-gateway def1\"\n").sendsAllIpv4ThroughTunnel({"redirect-gateway"}));

    // Split-tunnel profiles that drop every pushed redirect.
    QVERIFY(!analyzeOvpnRouting("pull-filter ignore \"redirect-gateway\"\nroute 10.0.0.0 255.0.0.0\n").sendsAllIpv4ThroughTunnel(pushDef1));
    QVERIFY(!analyzeOvpnRouting("route-nopull\n").sendsAllIpv4ThroughTunnel(pushDef1));
    // The helper strips route-noexec from the file, so it does not stop the profile's own redirect.
    QVERIFY(analyzeOvpnRouting("route-noexec\nredirect-gateway def1\n").sendsAllIpv4ThroughTunnel(noPush));
    // redirect-private in the file is stripped too; pushed, it enables no redirection.
    QVERIFY(!analyzeOvpnRouting("redirect-private local\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(!analyzeOvpnRouting("client\n").sendsAllIpv4ThroughTunnel({"redirect-private local"}));

    // Routes through the negotiated tunnel gateway (route-gateway) count like vpn_gateway.
    const QString ignoreRedirect = "pull-filter ignore redirect-gateway\n";
    QVERIFY(analyzeOvpnRouting(ignoreRedirect)
                .sendsAllIpv4ThroughTunnel({"route-gateway 10.8.0.1", "route 0.0.0.0 128.0.0.0 10.8.0.1",
                                            "route 128.0.0.0 128.0.0.0 10.8.0.1"}));
    // ...and through an address on the tunnel's own subnet (topology subnet).
    QVERIFY(analyzeOvpnRouting(ignoreRedirect)
                .sendsAllIpv4ThroughTunnel({"topology subnet", "ifconfig 10.8.0.6 255.255.255.0",
                                            "route 0.0.0.0 128.0.0.0 10.8.0.1", "route 128.0.0.0 128.0.0.0 10.8.0.1"}));
    // ...and through the net30 peer when no route-gateway is pushed.
    QVERIFY(analyzeOvpnRouting(ignoreRedirect)
                .sendsAllIpv4ThroughTunnel({"topology net30", "ifconfig 10.8.0.6 10.8.0.5",
                                            "route 0.0.0.0 128.0.0.0 10.8.0.5", "route 128.0.0.0 128.0.0.0 10.8.0.5"}));
    // A gateway outside the tunnel (the LAN router) is not the tunnel.
    QVERIFY(!analyzeOvpnRouting(ignoreRedirect)
                 .sendsAllIpv4ThroughTunnel({"route-gateway 10.8.0.1", "route 0.0.0.0 128.0.0.0 192.168.1.1",
                                             "route 128.0.0.0 128.0.0.0 192.168.1.1"}));
    // Coverage is computed over the address space, whatever the split.
    QVERIFY(analyzeOvpnRouting("route 0.0.0.0 192.0.0.0\nroute 64.0.0.0 192.0.0.0\nroute 128.0.0.0 192.0.0.0 vpn_gateway\n"
                               "route 192.0.0.0 192.0.0.0 default\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(!analyzeOvpnRouting("route 0.0.0.0 192.0.0.0\nroute 64.0.0.0 192.0.0.0\nroute 192.0.0.0 192.0.0.0\n")
                 .sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(analyzeOvpnRouting("route 0.0.0.0 0.0.0.0\n").sendsAllIpv4ThroughTunnel(noPush));
    // A non-contiguous netmask is not a route OpenVPN would install as such.
    QVERIFY(!analyzeOvpnRouting("route 0.0.0.0 128.0.0.0\nroute 128.0.0.0 255.0.255.0\n").sendsAllIpv4ThroughTunnel(noPush));

    // The point-to-point peer is a tunnel next hop even when a separate route-gateway is pushed.
    QVERIFY(analyzeOvpnRouting(ignoreRedirect)
                .sendsAllIpv4ThroughTunnel({"topology net30", "ifconfig 10.8.0.6 10.8.0.5", "route-gateway 10.8.0.1",
                                            "route 0.0.0.0 128.0.0.0 10.8.0.5", "route 128.0.0.0 128.0.0.0 10.8.0.5"}));

    // A more specific direct route wins over the tunnel for its addresses (longest prefix).
    QVERIFY(!analyzeOvpnRouting("route 0.0.0.0 128.0.0.0 vpn_gateway\nroute 128.0.0.0 128.0.0.0 vpn_gateway\n"
                                "route 203.0.113.0 255.255.255.0 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(!analyzeOvpnRouting("redirect-gateway def1\nroute 8.8.8.8 255.255.255.255 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    // ...unless the firewall lets those addresses through anyway: LAN ranges and the VPN server itself.
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\nroute 192.168.0.0 255.255.0.0 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\nroute 5.6.7.8 255.255.255.255 net_gateway\nremote 5.6.7.8 443\n")
                .sendsAllIpv4ThroughTunnel(noPush));
    // A direct /1 next to def1's /1 ties; a tie counts as the tunnel (OpenVPN installs both).
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\n").sendsAllIpv4ThroughTunnel({"route 0.0.0.0 128.0.0.0 net_gateway"}));
#ifdef Q_OS_WIN
    // On Windows the helper's --msg-channel makes OpenVPN add def1 to every redirect-gateway, so the
    // plain spelling installs the same two /1 routes and ties the same way.
    QVERIFY(analyzeOvpnRouting("redirect-gateway\n").sendsAllIpv4ThroughTunnel({"route 0.0.0.0 128.0.0.0 net_gateway"}));
#else
    // Without def1 the default route itself is replaced, so a direct /1 is more specific and wins.
    QVERIFY(!analyzeOvpnRouting("redirect-gateway\n").sendsAllIpv4ThroughTunnel({"route 0.0.0.0 128.0.0.0 net_gateway"}));
#endif
    // Private ranges routed locally keep the firewall on, including any overlap with Windscribe's
    // in-tunnel DNS range: the firewall blocks 10.255.255.0/24 off the tunnel on its own, and turning
    // the whole firewall off over it would remove far more protection than it keeps.
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\nroute 10.20.0.0 255.255.0.0 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\nroute 10.0.0.0 255.0.0.0 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    QVERIFY(analyzeOvpnRouting("redirect-gateway def1\nroute 10.255.255.0 255.255.255.0 net_gateway\n").sendsAllIpv4ThroughTunnel(noPush));
    // Inline data never holds routing directives.
    QVERIFY(!analyzeOvpnRouting("<auth-user-pass>\nredirect-gateway def1\n</auth-user-pass>\n").sendsAllIpv4ThroughTunnel(noPush));

    // Only an actual "remote 127.0.0.1" directive marks a local-wrapper config, not a comment.
    QVERIFY(customconfigs::hasLoopbackWrapperRemote("client\nremote 127.0.0.1\nport 1194\n"));
    QVERIFY(!customconfigs::hasLoopbackWrapperRemote("# via remote 127.0.0.1\nremote 5.6.7.8 443\n"));
    QVERIFY(!customconfigs::hasLoopbackWrapperRemote("remote 5.6.7.8 443 # not remote 127.0.0.1\n"));
    QVERIFY(!customconfigs::hasLoopbackWrapperRemote("remote 127.0.0.10 443\n"));
    // Same cases as the helper's hasLoopbackWrapperRemote test: inline data is not directives, a
    // <connection> block is.
    QVERIFY(!customconfigs::hasLoopbackWrapperRemote("remote 5.6.7.8 443\n<auth-user-pass>\nremote 127.0.0.1\nsecret\n</auth-user-pass>\n"));
    QVERIFY(!customconfigs::hasLoopbackWrapperRemote("<ca>\nremote 127.0.0.1\n</ca>\nremote 5.6.7.8 443\n"));
    QVERIFY(customconfigs::hasLoopbackWrapperRemote("<connection>\nremote 127.0.0.1 1194\n</connection>\n"));
    QVERIFY(!analyzeOvpnRouting("# remote 127.0.0.1\nroute 10.20.0.0 255.255.0.0\nremote 5.6.7.8 443\n")
                 .sendsAllIpv4ThroughTunnel(noPush));

    // Tokenizer: quotes group, escapes, comments.
    QCOMPARE(customconfigs::tokenizeOvpnLine("pull-filter ignore \"redirect-gateway ipv6\" # note"),
             QStringList({"pull-filter", "ignore", "redirect-gateway ipv6"}));
    QCOMPARE(customconfigs::tokenizeOvpnLine("  ; route 0.0.0.0 0.0.0.0"), QStringList());
    QCOMPARE(customconfigs::pushReplyOptions(">LOG:1,,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,ping 10'"),
             QStringList({"redirect-gateway def1", "ping 10"}));
}

void TestOpenVPNConnection::testPrepareCustomTcpWithLoopbackProxyProbesAndAppliesFix()
{
    QTcpServer proxy;
    QVERIFY(proxy.listen(QHostAddress::LocalHost, 0));

    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeProxySessionParams(proxy.serverPort()));
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    QSignalSpy failedSpy(&conn, &IConnection::prepareFailed);

    conn.prepare(makeCustomDescr(types::Protocol::OPENVPN_TCP,
                                 "dev tun\r\nredirect-gateway def1\r\nremote 5.6.7.8 443 tcp\r\n"),
                 makeEnv());

    // The probe is asynchronous: nothing is emitted until the proxy answers.
    QCOMPARE(preparedSpy.count(), 0);
    QVERIFY(preparedSpy.wait(5000));
    QCOMPARE(failedSpy.count(), 0);
    QVERIFY(conn.isProxyForwarded());
    // The config's routing is kept, and nothing the patched OpenVPN would reject is added to it.
    QVERIFY(conn.config_.contains("redirect-gateway def1"));
    QVERIFY(!conn.config_.contains("redirect-private"));
    // The profile's own redirect-gateway makes the tunnel full even without a pushed one.
    QVERIFY(conn.routingPolicy_.sendsAllIpv4ThroughTunnel(QStringList()));
}

void TestOpenVPNConnection::testPrepareTcpWithUnreachableProxyFails()
{
    // Take a free port and release it, so nothing listens there.
    quint16 port = 0;
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));
        port = server.serverPort();
    }

    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_TCP, makeProxySessionParams(port));
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);
    QSignalSpy failedSpy(&conn, &IConnection::prepareFailed);

    CurrentConnectionDescr descr = makeUdpDescr();
    descr.protocol = types::Protocol::OPENVPN_TCP;
    conn.prepare(descr, makeEnv());

    QVERIFY(failedSpy.wait(5000));
    QCOMPARE(failedSpy.first().first().value<ConnectError>(), ConnectError::kProxyUnreachable);
    QCOMPARE(preparedSpy.count(), 0);
}

void TestOpenVPNConnection::testPrepareCustomUdpWithProxyDoesNotUseIt()
{
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_UDP, makeProxySessionParams(9));
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);

    conn.prepare(makeCustomDescr(types::Protocol::OPENVPN_UDP,
                                 "dev tun\r\nredirect-gateway def1\r\nremote 5.6.7.8 1194 udp\r\n"),
                 makeEnv());

    // No probe and no rewrite: ConnectionManager refuses non-TCP attempts under a proxy before this point.
    QCOMPARE(preparedSpy.count(), 1);
    QVERIFY(!conn.isProxyForwarded());
    QVERIFY(!conn.config_.contains("redirect-private"));
    QVERIFY(conn.config_.contains("redirect-gateway def1"));
}

void TestOpenVPNConnection::testPrepareEmergencyTcpIgnoresProxy()
{
    OpenVpnSessionParams params = makeProxySessionParams(9);
    params.isEmergencyConnect = true;
    OpenVPNConnection conn(nullptr, helper_, types::Protocol::OPENVPN_TCP, params);
    QSignalSpy preparedSpy(&conn, &IConnection::prepared);

    CurrentConnectionDescr descr = makeUdpDescr();
    descr.protocol = types::Protocol::OPENVPN_TCP;
    conn.prepare(descr, makeEnv());

    QCOMPARE(preparedSpy.count(), 1);
    QVERIFY(!conn.isProxyForwarded());
    QVERIFY(!conn.config_.contains("redirect-private"));
}

QTEST_MAIN(TestOpenVPNConnection)
