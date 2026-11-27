#include "firewallpolicy.test.h"

#include <QtTest>

#include "engine/firewall/firewallcontroller.h"
#include "engine/firewall/firewallexceptions.h"
#include "engine/firewall/firewallpolicy.h"
#include "engine/requestproxysettings.h"
#include "types/proxysettings.h"
#include "utils/hardcodedsettings.h"
#include "../../../../../helper/common/dns_filter_ownership.h"

namespace {

// Records what the engine asks of the firewall.
class FakeFirewallController : public FirewallController
{
public:
    explicit FakeFirewallController(bool isOn) : FirewallController(nullptr), isOn_(isOn) {}

    void firewallOn(const QString &connectingIp, const QSet<QString> &ips, bool allowLan, bool isCustom, bool isVpnConnected,
                    const QSet<QString> &windscribeOnlyIps) override
    {
        FirewallController::firewallOn(connectingIp, ips, allowLan, isCustom, isVpnConnected, windscribeOnlyIps);
        isOn_ = true;
        isComplete_ = !failApply && failNextApplies <= 0;
        if (failNextApplies > 0) {
            --failNextApplies;
        }
        if (isComplete_) {
            // As the real controllers do: only a request applied successfully is committed.
            commitFirewallOn(connectingIp, ips, allowLan, isCustom, isVpnConnected, windscribeOnlyIps);
        }
        ++onCalls;
        lastConnectingIp = connectingIp;
        lastIps = ips;
        lastWindscribeOnlyIps = windscribeOnlyIps;
        lastIsVpnConnected = isVpnConnected;
    }
    void firewallOff() override
    {
        FirewallController::firewallOff();
        isOn_ = false;
        isComplete_ = true;
        ++offCalls;
    }
    bool firewallActualState() override
    {
        if (failNextStateQueries > 0) {
            --failNextStateQueries;
            return false;
        }
        return !failStateQuery && isOn_;
    }
    bool isFirewallComplete() const override { return isComplete_; }

    bool failApply = false;       // the helper reports the firewall incomplete (e.g. no DNS baseline)
    int failNextApplies = 0;      // only the next ones
    int failNextStateQueries = 0; // only the next state queries fail
    bool failStateQuery = false;  // the helper's state query fails (reads as off)
    bool isComplete_ = true;
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
    // Requests lost before the helper acts on them (it never saw them; the engine gets no answer).
    // A kFailed answer otherwise means the helper acted but could not change the rules.
    int dropNext = 0;
    QList<firewall_policy::DnsLeakFilter> sent;
    QList<QPair<quint64, int>> retries;
    // The rules the real helper has in place, from the engine's requests or a connector's, with the
    // helper's ownership rules (the real DnsLeakFilterOwnership).
    firewall_policy::DnsLeakFilter inPlace = firewall_policy::DnsLeakFilter::kOff;
    QList<firewall_policy::DnsLeakFilter> history;  // every change of inPlace, in order
    DnsLeakFilterOwnership ownership;

    void set(firewall_policy::DnsLeakFilter f)
    {
        if (f != inPlace) {
            inPlace = f;
            history << f;
        }
    }

    firewall_policy::ProxiedDnsLeakFilter makeController()
    {
        return firewall_policy::ProxiedDnsLeakFilter(
            [this](firewall_policy::DnsLeakFilter f) {
                using firewall_policy::DnsLeakFilterSendResult;
                sent << f;
                if (dropNext > 0) {
                    --dropNext;
                    return DnsLeakFilterSendResult::kFailed;
                }
                const auto answer = answers.isEmpty() ? DnsLeakFilterSendResult::kApplied : answers.takeFirst();
                if (!firewall_policy::isEnginesDnsLeakFilter(f)) {
                    if (!ownership.acceptDisable(DnsLeakFilterOwner::kProxiedSession)) {
                        return DnsLeakFilterSendResult::kApplied;  // a connector's filter: ignored
                    }
                    if (f == firewall_policy::DnsLeakFilter::kHandedOver) {
                        return answer;  // let go, rules left in place
                    }
                } else {
                    ownership.acceptEnable(DnsLeakFilterOwner::kProxiedSession);
                }
                if (answer != DnsLeakFilterSendResult::kFailed) {
                    set(f);
                }
                return answer;
            },
            [this](quint64 token, int delayMs) { retries << qMakePair(token, delayMs); });
    }

    // An OpenVPN connector without a proxy starting / ending (its run() enables / disables the filter).
    // installFails: the helper takes the request (the connector owns the filter) but cannot replace
    // the rules, which stay as they were. Returns what the helper answers.
    DnsLeakFilterResult connectorStarts(bool installFails = false)
    {
        if (!ownership.acceptEnable(DnsLeakFilterOwner::kConnection)) {
            return DnsLeakFilterResult::kIgnored;  // the engine holds the filter
        }
        if (installFails) {
            return DnsLeakFilterResult::kFailed;
        }
        set(firewall_policy::DnsLeakFilter::kBlockAll);
        return DnsLeakFilterResult::kApplied;
    }
    void connectorEnds()
    {
        if (ownership.acceptDisable(DnsLeakFilterOwner::kConnection)) {
            set(firewall_policy::DnsLeakFilter::kOff);
        }
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
    QVERIFY(!filter.mayConnect(true));                  // the connection is held
    QCOMPARE(helper.sent.size(), 2);                // it asked once more first
    QVERIFY(!helper.retries.isEmpty());             // and keeps retrying

    // The retry gets the blocks in: the next connect may go ahead.
    filter.onRetry(helper.retries.last().first);
    QVERIFY(filter.isBlockConfirmed());
    QVERIFY(filter.mayConnect(true));

    // Blocks in but a permit missing: blocks are what matters for connecting.
    FakeDnsLeakFilterHelper partial;
    partial.answers = {DnsLeakFilterSendResult::kIncomplete};
    auto filter2 = partial.makeController();
    filter2.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(filter2.mayConnect(true));
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
    QVERIFY(filter4.mayConnect(false));
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
    helper.connectorStarts();
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
    helper.connectorEnds();

    // The next proxied connection cannot install its rules: it must not be allowed on the old
    // confirmation.
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(!filter.mayConnect(true));
    QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    // Once the helper confirms, it may.
    QVERIFY(filter.mayConnect(true));
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
}

void TestFirewallPolicy::testReconnectNeedsNotConnectedRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(filter.mayStartAttempt(true));
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kBlockAll);  // connected rules in place

    // The tunnel drops. Windows rejects the reconnecting rules (local ranges, no custom DNS
    // exception): the connected rules stay, and they are not enough for an attempt.
    // (Two failures: the state change, then the check, which asks the helper once more.)
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    QVERIFY(filter.isBlockConfirmed());
    QVERIFY(!filter.mayStartAttempt(true));  // the connection manager's own retry is stopped
    QVERIFY(filter.mayStartAttempt(true));   // after the helper confirms, it goes ahead
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // The connection manager retrying before the engine has seen the reconnect (state still
    // CONNECTED, wanted still the connected rules) also gets the not-connected rules first.
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kBlockAll);
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    QVERIFY(!filter.mayStartAttempt(true));
    QCOMPARE(filter.wanted(), DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(filter.mayStartAttempt(true));

    // Sessions without a proxy are never stopped here.
    FakeDnsLeakFilterHelper none;
    auto plain = none.makeController();
    plain.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QVERIFY(plain.mayStartAttempt(false));
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

void TestFirewallPolicy::testLocationSwitchFromUnproxiedKeepsNewRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    // An ordinary OpenVPN session (no proxy) is connected; its connector holds the filter.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    helper.connectorStarts();
    filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);

    // The user turns the proxy on and picks another location: CONNECTING for the new session comes
    // before the old session is torn down, and the engine installs the new rules.
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // The old connector ends and disables the filter: ignored, it is the engine's now.
    helper.connectorEnds();
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
    // The new attempt goes ahead with the rules really in place.
    QVERIFY(filter.mayStartAttempt(true));
    QCOMPARE(helper.inPlace, filter.confirmed());

    // Through to the end of the proxied session.
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    filter.onConnectState(CONNECT_STATE_DISCONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, true, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    QVERIFY(!helper.ownership.hasOwner());
}

void TestFirewallPolicy::testNewUnproxiedSessionAfterErrorTakesOverFilter()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    // A proxied session ends with an error while the firewall stays on: the engine keeps its filter.
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, true, true);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // The proxy is turned off and a new session starts: it is not a reconnect of the proxied one. The
    // engine hands the filter over with its rules left in place; the connector replaces them.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QCOMPARE(filter.wanted(), DnsLeakFilter::kHandedOver);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(!helper.ownership.hasOwner());
    QVERIFY(filter.mayConnect(false));
    QVERIFY(filter.mayStartAttempt(false));
    helper.connectorStarts();
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kConnection);
    // Connected: the engine leaves the connector's rules alone.
    filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);
    QCOMPARE(filter.wanted(), DnsLeakFilter::kHandedOver);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    filter.onConnectState(CONNECT_STATE_DISCONNECTING, false, false);
    helper.connectorEnds();
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, false);
    QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);

    // Same, but the hand-over's removal fails: the helper still passes ownership on, and the engine's
    // retry, arriving once the connector holds the filter, is ignored.
    FakeDnsLeakFilterHelper failing;
    auto filter2 = failing.makeController();
    filter2.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter2.onConnectState(CONNECT_STATE_DISCONNECTED, true, true);
    failing.answers = {DnsLeakFilterSendResult::kFailed};
    filter2.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QCOMPARE(failing.inPlace, DnsLeakFilter::kPermitWindscribeApps);  // rules left in place
    QCOMPARE(failing.retries.size(), 1);
    failing.connectorStarts();
    QCOMPARE(failing.inPlace, DnsLeakFilter::kBlockAll);
    filter2.onRetry(failing.retries.last().first);
    QCOMPARE(failing.inPlace, DnsLeakFilter::kBlockAll);

    // A reconnect of a proxied session after the proxy was turned off keeps the engine's filter.
    FakeDnsLeakFilterHelper reconnect;
    auto filter3 = reconnect.makeController();
    filter3.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter3.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    filter3.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QCOMPARE(filter3.wanted(), DnsLeakFilter::kPermitWindscribeApps);
    QCOMPARE(reconnect.inPlace, DnsLeakFilter::kPermitWindscribeApps);
}

void TestFirewallPolicy::testProxiedRequestReplacingAttemptStillConnecting()
{
    using namespace firewall_policy;
    // The order Engine::connectClickImpl takes: the request is accepted (onConnectRequest) before the
    // earlier attempt is told to stop, and again once it has ended; then the connect check and the
    // connection manager's per-attempt check.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        // A direct attempt (no proxy) is still CONNECTING; its connector holds the filter.
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        helper.connectorStarts();
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
        const int historyBefore = helper.history.size();

        // The proxy is turned on and another profile picked: the state stays CONNECTING. The engine
        // accepts the proxied request while the old attempt is still running.
        filter.onConnectRequest(true, true);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
        // The old connector ends: ignored.
        helper.connectorEnds();
        // Re-entered once it has ended; then the checks.
        filter.onConnectRequest(true, false);
        QVERIFY(filter.mayConnect(true));
        QVERIFY(filter.mayStartAttempt(true));
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);

        // The filter was never off at any point of the hand-over.
        for (int i = historyBefore; i < helper.history.size(); ++i) {
            QVERIFY(helper.history[i] != DnsLeakFilter::kOff);
        }
        filter.onConnectState(CONNECT_STATE_DISCONNECTING, true, false);
        filter.onConnectState(CONNECT_STATE_DISCONNECTED, true, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    }
    // Fallback: the connection manager's own redial is the first to see a proxied request (its
    // request was updated underneath). The per-attempt check claims the filter before dialing.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        QVERIFY(filter.mayStartAttempt(true));
        QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
        QCOMPARE(helper.sent.size(), 1);
    }
    // And if the helper cannot install it, the attempt is stopped.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed,
                          DnsLeakFilterSendResult::kFailed};
        filter.onConnectRequest(true, true);
        QVERIFY(!filter.mayStartAttempt(true));
        QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    }
}

void TestFirewallPolicy::testDirectRequestReplacingProxiedSession()
{
    using namespace firewall_policy;
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        // A proxied session is connected; the engine holds the filter.
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        QVERIFY(filter.mayStartAttempt(true));
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);

        // The proxy is turned off and another profile picked. While the proxied session is still
        // being torn down it keeps its filter.
        const int historyBefore = helper.history.size();
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        filter.onConnectRequest(false, true);
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
        // Once it has ended, the new direct request takes over: its connector's rules are installed.
        filter.onConnectRequest(false, false);
        QVERIFY(filter.mayConnect(false));
        QVERIFY(filter.mayStartAttempt(false));
        helper.connectorStarts();
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kConnection);
        filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
        // No moment without a filter from the old session to the new one being connected.
        for (int i = historyBefore; i < helper.history.size(); ++i) {
            QVERIFY(helper.history[i] != DnsLeakFilter::kOff);
        }
        helper.connectorEnds();
        QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    }
    // The direct connection fails before its connector starts: the handed-over rules are removed
    // when the session ends.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        filter.onConnectRequest(false, false);
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
        filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    }
    // The old session's reconnect rules cannot be installed: the new direct request is not refused
    // for it, and its connector still gets the filter.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        filter.onConnectRequest(false, true);
        filter.onConnectRequest(false, false);
        QVERIFY(filter.mayConnect(false));
        QVERIFY(filter.mayStartAttempt(false));
        helper.connectorStarts();
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    }
    // An automatic retry of the proxied request itself keeps the engine's filter.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        QVERIFY(filter.mayStartAttempt(true));
        QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
    }
}

void TestFirewallPolicy::testRequestKeepsProxyChosenAtSelection()
{
    using namespace firewall_policy;
    const types::ProxySettings throne(PROXY_OPTION_HTTP, "127.0.0.1", 2080, "", "");
    const types::ProxySettings none;
    QVERIFY(!none.isProxyEnabled());

    RequestProxySettings request;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    // A direct session is connected; its connector holds the filter.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    helper.connectorStarts();
    filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);

    // A profile is picked with Throne enabled (connectClickImpl).
    request.onRequest(throne);
    filter.onConnectRequest(request.get(throne).isProxyEnabled(), true);
    // While the old session is torn down, the proxy is turned off in Preferences.
    helper.connectorEnds();
    // Re-entry after the old session ended, the request built, a credential-refresh redial: all with
    // the settings the profile was picked with.
    const types::ProxySettings used = request.get(none);
    QVERIFY(used.isProxyEnabled());
    QCOMPARE(used.address(), QString("127.0.0.1"));
    QCOMPARE(used.getPort(), static_cast<uint>(2080));
    filter.onConnectRequest(used.isProxyEnabled(), false);
    QVERIFY(filter.mayConnect(used.isProxyEnabled()));
    QVERIFY(filter.mayStartAttempt(used.isProxyEnabled()));
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);

    // Once the session is over, the next request takes the preference as it is then.
    request.onSessionEnded();
    QVERIFY(!request.get(none).isProxyEnabled());
}

void TestFirewallPolicy::testDroppedHandOverHoldsDirectAttempt()
{
    using namespace firewall_policy;
    const auto connectProxied = [](FakeDnsLeakFilterHelper &helper, ProxiedDnsLeakFilter &filter) {
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        QVERIFY(filter.mayStartAttempt(true));
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
        // The proxy is turned off and another profile picked; the old session is torn down.
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        filter.onConnectRequest(false, true);
    };
    // The hand-over is lost once: the check before the direct attempt sends it again.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        connectProxied(helper, filter);
        helper.dropNext = 1;
        filter.onConnectRequest(false, false);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);  // the helper never saw it
        QVERIFY(filter.mayConnect(false));
        QVERIFY(!helper.ownership.hasOwner());
        QVERIFY(filter.mayStartAttempt(false));
        helper.connectorStarts();
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kConnection);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
    }
    // The helper keeps not getting it: the direct attempt is held, the old rules stay, and nothing
    // removes them.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        connectProxied(helper, filter);
        const DnsLeakFilter rulesBefore = helper.inPlace;
        helper.dropNext = 3;
        filter.onConnectRequest(false, false);
        QVERIFY(!filter.mayConnect(false));
        QVERIFY(!filter.mayStartAttempt(false));
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
        QCOMPARE(helper.inPlace, rulesBefore);
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
        // A retry gets through later; then the attempt may go ahead.
        filter.onRetry(helper.retries.last().first);
        QVERIFY(filter.mayStartAttempt(false));
        QVERIFY(!helper.ownership.hasOwner());
    }
    // The held attempt ends the way the engine ends it: DISCONNECTED with an error, the firewall on.
    // The engine still holds its rules (the hand-over never arrived): they stay.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        connectProxied(helper, filter);
        helper.dropNext = 3;
        filter.onConnectRequest(false, false);
        QVERIFY(!filter.mayConnect(false));
        const quint64 pendingHandOver = helper.retries.last().first;
        filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);  // with error, firewall on
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
        QCOMPARE(filter.wanted(), DnsLeakFilter::kPermitWindscribeApps);
        // The hand-over retry, now stale, does nothing.
        const int sentBefore = helper.sent.size();
        filter.onRetry(pendingHandOver);
        QCOMPARE(helper.sent.size(), sentBefore);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
        // Turning the firewall off then removes them, as for any filter kept after an error.
        helper.dropNext = 0;
        filter.onFirewallOff(CONNECT_STATE_DISCONNECTED);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kOff);
    }
    // A connector whose session is connected keeps the handed-over filter until the session is over:
    // nothing removes the rules at CONNECTED.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        connectProxied(helper, filter);
        filter.onConnectRequest(false, false);
        QVERIFY(filter.mayConnect(false));
        const DnsLeakFilter left = helper.inPlace;
        filter.onConnectState(CONNECT_STATE_CONNECTED, false, false);  // before the connector claimed
        QCOMPARE(helper.inPlace, left);
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
    }
}

void TestFirewallPolicy::testEngineTrafficKeepsRequestProxy()
{
    const types::ProxySettings throne(PROXY_OPTION_HTTP, "127.0.0.1", 2080, "", "");
    const types::ProxySettings throneOtherPort(PROXY_OPTION_HTTP, "127.0.0.1", 3080, "", "");
    const types::ProxySettings none;

    for (const types::ProxySettings &changed : {none, throneOtherPort}) {
        RequestProxySettings request;
        // Start-up: the engine's own traffic follows the preference.
        auto update = request.engineTrafficUpdate(throne);
        QVERIFY(update.has_value());
        QVERIFY(*update == throne);

        // A connection through Throne; while it reconnects (a credential refresh pending), the
        // preference is turned off or its port changed.
        request.onRequest(throne);
        QVERIFY(!request.engineTrafficUpdate(changed).has_value());  // API keeps 127.0.0.1:2080
        // The credential request (restoreWsnetProxySettings) and the VPN redial (doConnect) both use
        // the request's proxy.
        QVERIFY(request.get(changed) == throne);
        QCOMPARE(request.get(changed).getPort(), static_cast<uint>(2080));

        // The session ends: now the changed preference applies.
        request.onSessionEnded();
        update = request.engineTrafficUpdate(changed);
        QVERIFY(update.has_value());
        QVERIFY(*update == changed);
        QVERIFY(!request.engineTrafficUpdate(changed).has_value());  // applied once
    }
}

void TestFirewallPolicy::testDirectConnectorNeedsItsOwnRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectRequest(true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    // Switch to a direct profile; the hand-over is confirmed.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    filter.onConnectRequest(false, true);
    filter.onConnectRequest(false, false);
    QVERIFY(filter.mayStartAttempt(false));
    const DnsLeakFilter engineRules = helper.inPlace;
    QVERIFY(engineRules != DnsLeakFilter::kOff);

    // The connector's own rules cannot be installed: the engine's (permissive for Windscribe and
    // Throne) stay, and the connector must not start its tunnel.
    const DnsLeakFilterResult result = helper.connectorStarts(true);
    QVERIFY(!isDnsLeakFilterInstalled(result));
    QCOMPARE(helper.inPlace, engineRules);
    // When they do go in (or only a permit is missing), it may.
    QVERIFY(isDnsLeakFilterInstalled(DnsLeakFilterResult::kApplied));
    QVERIFY(isDnsLeakFilterInstalled(DnsLeakFilterResult::kIncomplete));
}

void TestFirewallPolicy::testLocationSwitchAppliesNewRequestProxy()
{
    const types::ProxySettings throne(PROXY_OPTION_HTTP, "127.0.0.1", 2080, "", "");
    const types::ProxySettings none;
    RequestProxySettings request;
    // A direct session: the engine's traffic is direct.
    QVERIFY(request.engineTrafficUpdate(none).has_value());
    request.onRequest(none);
    QVERIFY(!request.engineTrafficUpdate(none).has_value());
    // Throne is turned on during the session: held until the session ends...
    QVERIFY(!request.engineTrafficUpdate(throne).has_value());
    // ...but an imported profile is picked now, without a disconnect in between. Accepting the
    // request (connectClickImpl) applies its proxy to the firewall exception and the probes at once.
    request.onRequest(throne);
    const auto update = request.engineTrafficUpdate(throne);
    QVERIFY(update.has_value());
    QVERIFY(*update == throne);
    QVERIFY(update->isProxyEnabled());  // direct probes of imported servers off
}

void TestFirewallPolicy::testConnectedReportedOnlyWithConnectedRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    // Throne on throughout. Connecting: the not-connected rules (Windscribe and Throne may resolve).
    filter.onConnectRequest(true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(filter.mayStartAttempt(true));
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);

    // The tunnel is up; Windows rejects the connected rules (twice: the change and one more try).
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    QVERIFY(!filter.mayReportConnected());  // the engine disconnects with an error instead
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kPermitWindscribeApps);
    // The engine's error disconnect, firewall on: the not-connected rules stay.
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, true, true);
    QVERIFY(helper.inPlace != DnsLeakFilter::kOff);

    // When they go in, the session may be reported connected, with them in place.
    FakeDnsLeakFilterHelper ok;
    auto filter2 = ok.makeController();
    filter2.onConnectRequest(true, false);
    filter2.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    ok.answers = {DnsLeakFilterSendResult::kFailed};  // first try fails, the second goes in
    QVERIFY(filter2.mayReportConnected());
    QCOMPARE(ok.inPlace, DnsLeakFilter::kBlockAll);
    const int sentBefore = ok.sent.size();
    filter2.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QCOMPARE(ok.sent.size(), sentBefore);  // nothing more to do

    // A direct session is never held here.
    FakeDnsLeakFilterHelper none;
    auto filter3 = none.makeController();
    filter3.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QVERIFY(filter3.mayReportConnected());
}

void TestFirewallPolicy::testLostHandOverReplyReclaimsFilter()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectRequest(true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    filter.onConnectRequest(false, true);
    // The helper acts on the hand-over (and on the one more try) but the answers are lost.
    helper.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed};
    filter.onConnectRequest(false, false);
    QVERIFY(!helper.ownership.hasOwner());  // the helper let go, and stopped watching
    QVERIFY(!filter.mayConnect(false));     // the direct attempt is held
    // The engine's error disconnect, firewall on: the engine claims its rules back explicitly.
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);
    QVERIFY(helper.ownership.hasOwner());
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
    QCOMPARE(filter.confirmed(), DnsLeakFilter::kPermitWindscribeApps);
    QVERIFY(helper.inPlace != DnsLeakFilter::kOff);

    // If the claim's answer is lost as well, it is retried until confirmed.
    FakeDnsLeakFilterHelper helper2;
    auto filter2 = helper2.makeController();
    filter2.onConnectRequest(true, false);
    filter2.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter2.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    filter2.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    filter2.onConnectRequest(false, true);
    helper2.answers = {DnsLeakFilterSendResult::kFailed, DnsLeakFilterSendResult::kFailed,
                       DnsLeakFilterSendResult::kFailed};
    filter2.onConnectRequest(false, false);
    QVERIFY(!filter2.mayConnect(false));
    filter2.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);
    QVERIFY(!filter2.isBlockConfirmed());
    filter2.onRetry(helper2.retries.last().first);
    QVERIFY(filter2.isBlockConfirmed());
    QVERIFY(helper2.ownership.hasOwner());
    QVERIFY(helper2.ownership.hasOwner() && helper2.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
}

void TestFirewallPolicy::testSecondFailedHandOverBeforeReclaimKeepsRules()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectRequest(true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);

    // Switch to a direct profile. The helper never gets the hand-over, the one more try, nor the
    // reclaim after the error.
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    filter.onConnectRequest(false, true);
    helper.dropNext = 3;
    filter.onConnectRequest(false, false);
    QVERIFY(!filter.mayConnect(false));
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);  // error, firewall on
    QVERIFY(!filter.isBlockConfirmed());                             // the reclaim is pending
    QVERIFY(helper.inPlace != DnsLeakFilter::kOff);

    // The user tries the direct profile again before the reclaim was confirmed; that hand-over is lost
    // too, and the attempt ends with an error again.
    helper.dropNext = 2;
    filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
    QCOMPARE(filter.wanted(), DnsLeakFilter::kHandedOver);
    QVERIFY(!filter.mayConnect(false));
    filter.onConnectState(CONNECT_STATE_DISCONNECTED, false, true);

    // The rules are still there (as the not-connected ones kept after an error), and the engine has
    // claimed them back.
    QVERIFY(helper.inPlace != DnsLeakFilter::kOff);
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
    QVERIFY(isEnginesDnsLeakFilter(filter.wanted()));
    QVERIFY(filter.isBlockConfirmed());
    // The filter was never off at any point.
    QVERIFY(!helper.history.contains(DnsLeakFilter::kOff));
}

void TestFirewallPolicy::testDirectWireGuardOrIkev2AfterProxiedOpenVpn()
{
    // WireGuard (also AmneziaWG) and IKEv2 on Windows enable the filter before starting the tunnel
    // and do not start it unless isDnsLeakFilterInstalled(), like OpenVPN without a proxy. The
    // connector here stands for any of them.
    using namespace firewall_policy;
    const auto proxiedThenSwitch = [](FakeDnsLeakFilterHelper &helper, ProxiedDnsLeakFilter &filter) {
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTED, true, false);
        QCOMPARE(helper.inPlace, DnsLeakFilter::kBlockAll);
        filter.onConnectState(CONNECT_STATE_CONNECTING, false, false);
        filter.onConnectRequest(false, true);
    };
    // kFailed: the hand-over went through, but the connector's rules cannot be installed. It does
    // not start; it releases what it took, as its teardown does.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        proxiedThenSwitch(helper, filter);
        filter.onConnectRequest(false, false);
        QVERIFY(filter.mayStartAttempt(false));
        const DnsLeakFilterResult result = helper.connectorStarts(true);
        QCOMPARE(result, DnsLeakFilterResult::kFailed);
        QVERIFY(!isDnsLeakFilterInstalled(result));
        QVERIFY(helper.inPlace != DnsLeakFilter::kOff);  // nothing changed while it decided not to start
        helper.connectorEnds();
        QVERIFY(!helper.ownership.hasOwner());
    }
    // kIgnored: the connector got there while the engine still held the filter (the hand-over was not
    // through). It does not start; its release is ignored too, so the engine's rules stay.
    {
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        proxiedThenSwitch(helper, filter);
        const DnsLeakFilter engineRules = helper.inPlace;
        const DnsLeakFilterResult result = helper.connectorStarts();
        QCOMPARE(result, DnsLeakFilterResult::kIgnored);
        QVERIFY(!isDnsLeakFilterInstalled(result));
        helper.connectorEnds();
        QCOMPARE(helper.inPlace, engineRules);
        QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
    }
}

void TestFirewallPolicy::testIgnoredConnectorRequestIsNotInstalled()
{
    using namespace firewall_policy;
    FakeDnsLeakFilterHelper helper;
    auto filter = helper.makeController();
    filter.onConnectRequest(true, false);
    filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
    QVERIFY(helper.ownership.hasOwner() && helper.ownership.owner() == DnsLeakFilterOwner::kProxiedSession);
    // A direct connector's request while the engine holds the filter is ignored: its rules are not
    // in, and it must not start its tunnel.
    const DnsLeakFilterResult result = helper.connectorStarts();
    QCOMPARE(result, DnsLeakFilterResult::kIgnored);
    QVERIFY(!isDnsLeakFilterInstalled(result));
    QCOMPARE(helper.inPlace, DnsLeakFilter::kPermitWindscribeApps);
}

void TestFirewallPolicy::testFailedBaselineHoldsConnectionDespiteSessionFilter()
{
    using namespace firewall_policy;
    int resends = 0;
    const auto resend = [&resends]() { ++resends; };

    // Automatic / Before Connection: the firewall is turned on before connecting and the helper
    // reports it incomplete (no DNS baseline). The session DNS leak filter goes in fine, but the
    // engine does not connect, nor start an attempt.
    {
        FakeFirewallController controller(false);
        controller.failApply = true;
        controller.firewallOn("", {}, true, true, false, {});
        FakeDnsLeakFilterHelper helper;
        auto filter = helper.makeController();
        filter.onConnectRequest(true, false);
        filter.onConnectState(CONNECT_STATE_CONNECTING, true, false);
        QVERIFY(filter.mayConnect(true));
        QVERIFY(!ensureFirewallReady(controller, resend));
        QVERIFY(filter.mayStartAttempt(true));
        QVERIFY(!ensureFirewallReady(controller, resend));
        QVERIFY(resends > 0);
    }
    // Automatic / After Connection: off while connecting (nothing to hold), turned on once the tunnel
    // is up; that activation fails. Checked after it, in the engine's order, it is not reported
    // connected. (Checked before it, as the engine used to, it would have passed.)
    {
        FakeFirewallController controller(false);
        controller.failApply = true;
        QVERIFY(ensureFirewallReady(controller, resend));  // intentionally off while connecting
        const auto action = afterConnected(FIREWALL_MODE_AUTOMATIC, FIREWALL_WHEN_AFTER_CONNECTION,
                                           controller.firewallActualState(), true);
        QCOMPARE(action, AutomaticAction::TurnOn);
        controller.firewallOn("", {}, true, true, true, {});
        QVERIFY(!ensureFirewallReady(controller, resend));
    }
    // The helper's state query fails: wanted on but unknown is not ready (not taken as "off").
    {
        FakeFirewallController controller(false);
        controller.firewallOn("", {}, true, true, false, {});
        controller.failStateQuery = true;
        QVERIFY(!ensureFirewallReady(controller, resend));
    }
    // Complete and on, or meant to be off: ready.
    {
        FakeFirewallController on(false);
        on.firewallOn("", {}, true, true, false, {});
        QVERIFY(ensureFirewallReady(on, resend));
        FakeFirewallController off(false);
        QVERIFY(ensureFirewallReady(off, resend));
        on.firewallOff();
        QVERIFY(ensureFirewallReady(on, resend));
    }
}

void TestFirewallPolicy::testConnectedRetrySendsConnectedRules()
{
    using namespace firewall_policy;
    FirewallExceptions exceptions = makeExceptions(true);
    const QSet<QString> connected = exceptions.getIPAddressesForFirewallForConnectedState();
    // The not-connected request is told apart by its connected flag and its Windscribe-only DNS list
    // (here the address lists happen to be the same).
    QVERIFY(!exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true).isEmpty());

    FakeFirewallController controller(true);
    // The tunnel is up; the connected-state request is not applied completely the first time.
    controller.failNextApplies = 1;
    applyConnectedState(controller, exceptions, "203.0.113.5", true, true);
    QVERIFY(!controller.isFirewallComplete());
    // The check before reporting connected retries with the same connected-state request (the
    // engine's resend for that check), which succeeds.
    const bool isReady = ensureFirewallReady(
        controller, [&]() { applyConnectedState(controller, exceptions, "203.0.113.5", true, true); });
    QVERIFY(isReady);
    QCOMPARE(controller.onCalls, 2);
    // What reached the helper last: the connected rules, not the not-connected ones.
    QVERIFY(controller.lastIsVpnConnected);
    QCOMPARE(controller.lastIps, connected);
    QCOMPARE(controller.lastConnectingIp, QString("203.0.113.5"));
    QVERIFY(controller.lastWindscribeOnlyIps.isEmpty());
}

void TestFirewallPolicy::testConnectedReportNeedsConnectedRequest()
{
    using namespace firewall_policy;
    FirewallExceptions exceptions = makeExceptions(true);
    const auto applyConnected = [&](FakeFirewallController &controller) {
        applyConnectedState(controller, exceptions, "203.0.113.5", true, true);
    };

    // Always On: the connecting-state rules are in and complete.
    FakeFirewallController controller(false);
    controller.firewallOn(exceptions.connectingIp(), exceptions.getIPAddressesForNotConnectedState(false, true), true, true,
                          false, exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true));
    QVERIFY(controller.isFirewallComplete());
    QVERIFY(!controller.isConnectedStateCommitted());
    const int callsBefore = controller.onCalls;

    // The tunnel is up; the first status read fails. The engine still applies the connected rules,
    // since the firewall is meant to be on.
    controller.failNextStateQueries = 1;
    const bool isApplied = shouldApplyConnectedFirewall(controller.isFirewallWanted(), controller.firewallActualState());
    QVERIFY(isApplied);
    applyConnected(controller);
    QCOMPARE(controller.onCalls, callsBefore + 1);
    QVERIFY(controller.lastIsVpnConnected);
    QVERIFY(ensureConnectedFirewallReady(controller, [&]() { applyConnected(controller); }));

    // Had that apply been skipped (as before), the final check does not accept the complete
    // connecting-state firewall: it sends the connected request, and only then is it ready.
    FakeFirewallController skipped(false);
    skipped.firewallOn(exceptions.connectingIp(), exceptions.getIPAddressesForNotConnectedState(false, true), true, true,
                       false, exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true));
    skipped.failNextStateQueries = 1;
    QVERIFY(!skipped.firewallActualState());  // the read that failed
    QVERIFY(skipped.firewallActualState());   // the next one succeeds
    const int skippedCalls = skipped.onCalls;
    QVERIFY(ensureConnectedFirewallReady(skipped, [&]() { applyConnected(skipped); }));
    QCOMPARE(skipped.onCalls, skippedCalls + 1);
    QVERIFY(skipped.lastIsVpnConnected);
    QCOMPARE(skipped.lastConnectingIp, QString("203.0.113.5"));
    QVERIFY(skipped.lastWindscribeOnlyIps.isEmpty());

    // And if that connected request is not applied completely either: not ready.
    FakeFirewallController failing(false);
    failing.firewallOn(exceptions.connectingIp(), exceptions.getIPAddressesForNotConnectedState(false, true), true, true,
                       false, exceptions.getWindscribeOnlyIPAddressesForNotConnectedState(false, true));
    failing.failApply = true;
    QVERIFY(!ensureConnectedFirewallReady(failing, [&]() { applyConnected(failing); }));
}

void TestFirewallPolicy::testIpv6BlockGatesConnected()
{
    // The IPv6 block (an IPv4-only VPN, native IPv6 on the Wi-Fi, firewall off) must be in before
    // connected is reported: the helper's failure is not just logged.
    int retries = 0;
    const auto retryWorks = [&]() { ++retries; return true; };
    const auto retryFails = [&]() { ++retries; return false; };

    QVERIFY(firewall_policy::ensureStepApplied(true, retryFails));
    QCOMPARE(retries, 0);

    QVERIFY(firewall_policy::ensureStepApplied(false, retryWorks));
    QCOMPARE(retries, 1);

    QVERIFY(!firewall_policy::ensureStepApplied(false, retryFails));
    QCOMPARE(retries, 2);
}

void TestFirewallPolicy::testProxiedSplitTunnelFailureEndsAttemptKeepsSettings()
{
    using firewall_policy::SplitTunnelStartAction;
    // The user's saved split tunneling settings: Exclusive, Throne and its core excluded.
    struct Saved {
        bool isActive = true;
        bool isExclusive = true;
        QStringList apps = {"throne.exe", "sing-box.exe"};
    } saved;
    struct Outcome {
        bool isConnected = false;
        bool isError = false;
    };
    // Engine::onConnectionManagerConnected for a proxied session (built-in or imported OpenVPN TCP
    // profile alike), with the GUI's reaction to splitTunnelingStartFailed (it turns the preference off).
    QStringList appliedApps;
    const auto attempt = [&](bool isHelperApplied) {
        Outcome outcome;
        switch (firewall_policy::splitTunnelStartAction(isHelperApplied, true, saved.isActive, saved.isExclusive)) {
        case SplitTunnelStartAction::kEndAttempt:
            outcome.isError = true;
            return outcome;
        case SplitTunnelStartAction::kWarnAndDisable:
            saved.isActive = false;
            break;
        case SplitTunnelStartAction::kContinue:
            appliedApps = saved.apps;
            break;
        }
        outcome.isConnected = true;
        return outcome;
    };

    // The helper reports failure: not connected, an error, the settings untouched.
    const Outcome failed = attempt(false);
    QVERIFY(!failed.isConnected && failed.isError);
    QVERIFY(saved.isActive && saved.isExclusive);
    QCOMPARE(saved.apps, QStringList({"throne.exe", "sing-box.exe"}));

    // The next attempt succeeds, with the exclusions.
    const Outcome next = attempt(true);
    QVERIFY(next.isConnected && !next.isError);
    QCOMPARE(appliedApps, QStringList({"throne.exe", "sing-box.exe"}));

    // Upstream handling elsewhere: without a proxy, or in Inclusive mode, a failure warns (the GUI then
    // turns split tunneling off) and the connection goes on.
    QVERIFY(firewall_policy::splitTunnelStartAction(false, false, true, true) == SplitTunnelStartAction::kWarnAndDisable);
    QVERIFY(firewall_policy::splitTunnelStartAction(false, true, true, false) == SplitTunnelStartAction::kWarnAndDisable);
    QVERIFY(firewall_policy::splitTunnelStartAction(false, true, false, true) == SplitTunnelStartAction::kWarnAndDisable);
    QVERIFY(firewall_policy::splitTunnelStartAction(true, true, true, true) == SplitTunnelStartAction::kContinue);
}

namespace {
// The Windows helper's split tunneling, as the engine sees it through setSplitTunnelingSettings and
// the report that comes with each sendConnectStatus.
struct FakeSplitTunnelHelper {
    firewall_policy::SplitTunnelState settings;  // what it applies (a fresh one: off, no apps)
    QStringList unidentifiable;                  // programs it cannot identify (they exist)
    int settingsSent = 0;
    void restart() { settings = firewall_policy::SplitTunnelState(); }
    void setSettings(const firewall_policy::SplitTunnelState &s)
    {
        ++settingsSent;
        settings = s;
    }
    bool sendConnectStatus() { return true; }  // the status itself applies
    firewall_policy::SplitTunnelState report() const
    {
        firewall_policy::SplitTunnelState r = settings;
        for (const QString &app : settings.apps) {
            if (unidentifiable.contains(app)) {
                r.areAppsResolved = false;
            }
        }
        return r;
    }
    // The exclusions that have rules.
    QStringList excludedWithRules() const
    {
        QStringList apps;
        for (const QString &app : settings.apps) {
            if (!unidentifiable.contains(app)) {
                apps << app;
            }
        }
        return apps;
    }
};

firewall_policy::SplitTunnelState throneExclusions()
{
    firewall_policy::SplitTunnelState s;
    s.isActive = true;
    s.isExclusive = true;
    s.apps = {"C:/Throne/throne.exe", "C:/Throne/sing-box.exe"};
    return s;
}

// Engine::onConnectionManagerConnected for a proxied Exclusive session: whether connected is shown.
bool connectedAttempt(FakeSplitTunnelHelper &helper, const firewall_policy::SplitTunnelState &requested)
{
    const bool isApplied = firewall_policy::ensureSplitTunnelConfirmed(
        helper.sendConnectStatus(), requested, [&]() { return helper.report(); },
        [&]() { helper.setSettings(requested); return helper.sendConnectStatus(); });
    return firewall_policy::splitTunnelStartAction(isApplied, true, requested.isActive, requested.isExclusive) ==
           firewall_policy::SplitTunnelStartAction::kContinue;
}
} // namespace

void TestFirewallPolicy::testRestartedHelperSplitTunnelIsReapplied()
{
    const firewall_policy::SplitTunnelState requested = throneExclusions();
    FakeSplitTunnelHelper helper;
    helper.setSettings(requested);

    // The helper restarts between receiving the settings and the connected status: it reports its
    // defaults (and the status applied). The settings are sent again, then confirmed.
    helper.restart();
    QVERIFY(!firewall_policy::isSplitTunnelConfirmed(requested, helper.report()));
    QVERIFY(connectedAttempt(helper, requested));
    QCOMPARE(helper.settingsSent, 2);
    QCOMPARE(helper.excludedWithRules(), requested.apps);

    // Settings in place from the start: no resend.
    QVERIFY(connectedAttempt(helper, requested));
    QCOMPARE(helper.settingsSent, 2);

    // A helper that keeps losing them (it restarts again during the resend): not connected.
    struct Restarting : FakeSplitTunnelHelper {
        bool sendConnectStatus() { restart(); return true; }
    } restarting;
    const bool isApplied = firewall_policy::ensureSplitTunnelConfirmed(
        restarting.sendConnectStatus(), requested, [&]() { return restarting.report(); },
        [&]() { restarting.setSettings(requested); return restarting.sendConnectStatus(); });
    QVERIFY(!isApplied);
}

void TestFirewallPolicy::testUnresolvedExcludedAppIsNotConfirmed()
{
    // throne.exe is identified, sing-box.exe (the core that reaches the VLESS server) is not.
    const firewall_policy::SplitTunnelState requested = throneExclusions();
    FakeSplitTunnelHelper helper;
    helper.setSettings(requested);
    helper.unidentifiable = {"C:/Throne/sing-box.exe"};
    QVERIFY(!connectedAttempt(helper, requested));  // the resend does not help: the attempt ends
    QCOMPARE(helper.excludedWithRules(), QStringList({"C:/Throne/throne.exe"}));
    QCOMPARE(requested.apps.size(), 2);  // the saved exclusions are untouched

    // The next attempt, once it can be identified, uses both exclusions.
    helper.unidentifiable.clear();
    QVERIFY(connectedAttempt(helper, requested));
    QCOMPARE(helper.excludedWithRules(), requested.apps);
}

QTEST_MAIN(TestFirewallPolicy)
