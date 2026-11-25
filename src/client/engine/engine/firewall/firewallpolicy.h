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

// Windows DNS leak filter (port 53 to the physical adapters' DNS servers) for a session started with a
// proxy set. It is on from the first CONNECTING to the final DISCONNECTED, reconnects and the gaps
// between OpenVPN processes included. While not connected Windscribe's programs and Exclusive-mode
// excluded apps are permitted (kPermitWindscribeApps) and every local-network range is blocked for the
// rest; while connected every program is blocked from the adapters' resolvers.
// A session that ends without the user's Disconnect (proxy unreachable, route error, sleep) while the
// firewall stays on keeps it (keepAfterSession) until the firewall goes off or the next session.
enum class DnsLeakFilter { kOff, kPermitWindscribeApps, kBlockAll };

struct DnsLeakFilterStep
{
    DnsLeakFilter next;
    bool apply;  // send next to the helper
};

DnsLeakFilterStep proxiedDnsLeakFilter(DnsLeakFilter current, CONNECT_STATE state, bool isProxySet,
                                       bool keepAfterSession = false);
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
    bool isBlockConfirmed() const { return isBlockConfirmed_; }
    // Whether a proxied connection may start: the filter is not the engine's, or the helper has
    // confirmed a block. If not, it asks the helper once more first.
    bool mayConnect();

private:
    void apply(const DnsLeakFilterStep &step);
    void send();

    Send send_;
    ScheduleRetry scheduleRetry_;
    DnsLeakFilter wanted_ = DnsLeakFilter::kOff;
    bool isBlockConfirmed_ = false;
    quint64 token_ = 0;
    int retryDelayMs_ = kFirstRetryMs;
};

} // namespace firewall_policy
