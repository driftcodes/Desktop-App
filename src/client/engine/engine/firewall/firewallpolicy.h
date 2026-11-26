#pragma once

#include <functional>
#include <QtGlobal>
#include <QSet>
#include <QString>
#include "types/enums.h"

class FirewallController;
class FirewallExceptions;

// Firewall decisions the engine takes at connection-state changes, kept out of Engine so they can be
// tested against a fake controller.
namespace firewall_policy {

enum class AutomaticAction { None, TurnOn, TurnOff };

// What the automatic firewall does once a connection is up. Only FIREWALL_MODE_AUTOMATIC acts:
// "after connection" turns it on when the tunnel carries all traffic; "before connection" turns it off
// when it does not (the profile wants traffic outside the tunnel that the firewall would block).
// The Always On modes never change it here.
AutomaticAction afterConnected(FIREWALL_MODE mode, FIREWALL_WHEN when, bool isFirewallOn, bool tunnelCarriesAllTraffic);

// Leaving a connection (disconnect, or a terminal error after dialing): forgets its exceptions (the
// server it dialed, its DNS servers) and, if the firewall is on, re-applies it for the not-connected
// state with notConnectedIps() (every program) and windscribeOnlyIps() (Windscribe's programs only).
// It never turns the firewall on or off.
void leaveConnection(FirewallController &controller, FirewallExceptions &exceptions,
                     const std::function<QSet<QString>()> &notConnectedIps,
                     const std::function<QSet<QString>()> &windscribeOnlyIps, bool allowLanTraffic, bool isCustomConfig);

// With the firewall wanted on, a connection (and each attempt, and reporting it connected) needs it
// applied completely and actually on: on Windows that includes the DNS baseline, without which the
// helper holds the LAN permit back and reports it incomplete; a failed state query counts as not on.
// The session DNS leak filter being in place does not make up for it. A firewall that is meant to
// be off (Automatic before it turns on) does not hold anything.
inline bool isFirewallReady(bool isWanted, bool isComplete, bool isActuallyOn)
{
    return !isWanted || (isComplete && isActuallyOn);
}

// The connected state's firewall request: the server it connected to, the connected-state exceptions.
// The engine applies it once the tunnel is up and, if the helper did not apply it completely, sends
// exactly this again before reporting connected (not the not-connected rules, which the generic
// update would pick while the connect state still says CONNECTING).
void applyConnectedState(FirewallController &controller, FirewallExceptions &exceptions, const QString &connectedIp,
                         bool allowLanTraffic, bool isCustomConfig);

// Whether the engine applies the connected-state firewall once the tunnel is up: when the firewall is
// meant to be on, also if a status query fails then (the query alone decided before).
inline bool shouldApplyConnectedFirewall(bool isWanted, bool isActuallyOnQuery)
{
    return isWanted || isActuallyOnQuery;
}

// Before reporting connected: like ensureFirewallReady, but the request applied completely must be the
// connected-state one (resendConnected() sends it). A complete connecting-state firewall is not.
bool ensureConnectedFirewallReady(FirewallController &controller, const std::function<void()> &resendConnected);

// isFirewallReady for the controller, resending once (resend()) if it is not: what the engine checks
// before connecting, before each attempt and before reporting connected.
bool ensureFirewallReady(FirewallController &controller, const std::function<void()> &resend);

// Windows DNS leak filter (port 53 to the physical adapters' DNS servers) for a session started with a
// proxy set. It is on from the first CONNECTING to the final DISCONNECTED, reconnects and the gaps
// between OpenVPN processes included. While not connected Windscribe's programs and Exclusive-mode
// excluded apps are permitted (kPermitWindscribeApps) and every local-network range is blocked for the
// rest; while connected every program is blocked from the adapters' resolvers.
// A session that ends without the user's Disconnect (proxy unreachable, route error, sleep) while the
// firewall stays on keeps it (keepAfterSession) until the firewall goes off or the next session.
// kHandedOver: the engine let go of the filter for a connection without a proxy but left its rules in
// place; that connection's connector replaces them in one step when it starts (no moment without a
// filter). The direct attempt starts only once the helper has confirmed the hand-over (otherwise the
// helper would still ignore the connector). The engine removes the rules when the session is over,
// which the helper ignores if the connector holds the filter by then.
enum class DnsLeakFilter { kOff, kPermitWindscribeApps, kBlockAll, kHandedOver };

// The engine holds the filter (kPermitWindscribeApps or kBlockAll).
inline bool isEnginesDnsLeakFilter(DnsLeakFilter f)
{
    return f == DnsLeakFilter::kPermitWindscribeApps || f == DnsLeakFilter::kBlockAll;
}

struct DnsLeakFilterStep
{
    DnsLeakFilter next;
    bool apply;  // send next to the helper
};

// isNewSession: CONNECTING straight from DISCONNECTED (a connect, not a reconnect or a location
// switch of a running session). A new session without a proxy hands the filter back to its connector,
// also one kept after a proxied session's error; a reconnect of a proxied session keeps it even if
// the proxy was turned off meanwhile.
DnsLeakFilterStep proxiedDnsLeakFilter(DnsLeakFilter current, CONNECT_STATE state, bool isProxySet,
                                       bool keepAfterSession = false, bool isNewSession = false);
// Windows reported a network change: rebuild an active filter for the new adapters' DNS servers.
DnsLeakFilterStep proxiedDnsLeakFilterOnNetworkChange(DnsLeakFilter current);
// The firewall was turned off: a filter kept after a session ends with it.
DnsLeakFilterStep proxiedDnsLeakFilterAfterFirewallOff(DnsLeakFilter current, CONNECT_STATE state);

// What the helper reported for a change (mirrors DnsLeakFilterResult in helper_commands.h).
enum class DnsLeakFilterSendResult {
    kFailed,      // nothing changed: the rules in place before stay
    kIncomplete,  // blocks in place, something else missing; retried
    kApplied
};

// Drives the proxied DNS leak filter for the engine: sends the filter each state wants, knows whether
// a block is confirmed in place, and retries until the helper confirms the wanted filter. A retry
// carries a token; any later send or a change of owner (a session the engine does not handle, whose
// connector manages the filter itself) invalidates it, so a late retry never undoes newer rules.
class ProxiedDnsLeakFilter
{
public:
    using Send = std::function<DnsLeakFilterSendResult(DnsLeakFilter)>;
    using ScheduleRetry = std::function<void(quint64 token, int delayMs)>;
    static constexpr int kFirstRetryMs = 2000;
    static constexpr int kMaxRetryMs = 60000;

    ProxiedDnsLeakFilter(Send send, ScheduleRetry scheduleRetry);

    void onConnectState(CONNECT_STATE state, bool isProxySet, bool keepAfterSession);
    void onNetworkChange();
    void onFirewallOff(CONNECT_STATE state);
    void onShutdown();
    void onRetry(quint64 token);

    DnsLeakFilter wanted() const { return wanted_; }
    // The filter the helper last confirmed for the engine (blocks in place); kOff when none, or when
    // the filter has not been the engine's since (a connector without a proxy managed it).
    DnsLeakFilter confirmed() const { return confirmed_; }
    bool isBlockConfirmed() const { return isEnginesDnsLeakFilter(confirmed_); }
    // The engine accepted a connection request (a connect, a location switch, a redial it starts);
    // isProxied: whether that request uses the proxy, isPreviousSessionActive: whether an earlier
    // session is still being torn down. A proxied request claims the filter right away, before the
    // outgoing connector is told to stop, so its teardown is ignored. A request without a proxy hands
    // the filter to its own connector, but only once the earlier session is gone, so that session
    // keeps its protection while it ends.
    void onConnectRequest(bool isProxied, bool isPreviousSessionActive);

    // isProxied: whether the request being started uses the proxy (its own settings, not the connect
    // state: a request replacing an attempt still CONNECTING brings no new CONNECTING). A proxied
    // request while the filter is not the engine's makes the engine take it over first.
    // Whether a connection may start: the filter is not the engine's, or the helper has confirmed
    // exactly the wanted rules. If not, it asks the helper once more first.
    bool mayConnect(bool isProxied);
    // Before every attempt, the first and each retry the connection manager starts on its own: an
    // attempt is not connected, so a proxied session needs the not-connected rules (local ranges
    // blocked, no custom DNS exception) confirmed, not the connected ones still in place.
    bool mayStartAttempt(bool isProxied);
    // The tunnel is up, before the session is reported connected: the connected rules (every program
    // blocked from the adapters' resolvers) replace the not-connected ones, which still let Windscribe
    // and excluded apps reach them. false when the helper has not confirmed them (after one more
    // try); the session must not be reported connected then.
    bool mayReportConnected();

private:
    void apply(const DnsLeakFilterStep &step);
    void claimForProxiedRequest(bool isProxied);
    void send();

    Send send_;
    ScheduleRetry scheduleRetry_;
    DnsLeakFilter wanted_ = DnsLeakFilter::kOff;
    DnsLeakFilter confirmed_ = DnsLeakFilter::kOff;
    // The engine's rules the helper may still have in place, held by the engine: set whenever the
    // engine sends its rules (answered or not), cleared only when the helper confirms letting go. An
    // unconfirmed hand-over falls back to these and reclaims them, however many failed hand-overs
    // and reclaims came in between.
    DnsLeakFilter heldRules_ = DnsLeakFilter::kOff;
    CONNECT_STATE lastState_ = CONNECT_STATE_DISCONNECTED;
    quint64 token_ = 0;
    int retryDelayMs_ = kFirstRetryMs;
};

} // namespace firewall_policy
