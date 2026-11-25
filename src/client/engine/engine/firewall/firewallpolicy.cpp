#include "firewallpolicy.h"

#include "firewallcontroller.h"
#include "firewallexceptions.h"

namespace firewall_policy {

AutomaticAction afterConnected(FIREWALL_MODE mode, FIREWALL_WHEN when, bool isFirewallOn, bool tunnelCarriesAllTraffic)
{
    if (mode != FIREWALL_MODE_AUTOMATIC) {
        return AutomaticAction::None;
    }
    if (tunnelCarriesAllTraffic && when == FIREWALL_WHEN_AFTER_CONNECTION && !isFirewallOn) {
        return AutomaticAction::TurnOn;
    }
    if (!tunnelCarriesAllTraffic && when == FIREWALL_WHEN_BEFORE_CONNECTION && isFirewallOn) {
        return AutomaticAction::TurnOff;
    }
    return AutomaticAction::None;
}

void leaveConnection(FirewallController &controller, FirewallExceptions &exceptions,
                     const std::function<QSet<QString>()> &notConnectedIps,
                     const std::function<QSet<QString>()> &windscribeOnlyIps, bool allowLanTraffic, bool isCustomConfig)
{
    exceptions.clearConnectionExceptions();
    if (controller.firewallActualState()) {
        controller.firewallOn(exceptions.connectingIp(), notConnectedIps(), allowLanTraffic, isCustomConfig, false,
                              windscribeOnlyIps());
    }
}

DnsLeakFilterStep proxiedDnsLeakFilter(DnsLeakFilter current, CONNECT_STATE state, bool isProxySet, bool keepAfterSession)
{
    switch (state) {
    case CONNECT_STATE_CONNECTING:
        // Entered once per connect or reconnect: the state controller does not repeat CONNECTING for
        // further attempts, so network changes are handled by proxiedDnsLeakFilterOnNetworkChange.
        // A session that started proxied keeps the filter even if the proxy is turned off meanwhile.
        if (current == DnsLeakFilter::kOff && !isProxySet) {
            return {current, false};
        }
        return {DnsLeakFilter::kPermitWindscribeApps, true};
    case CONNECT_STATE_CONNECTED:
        if (current == DnsLeakFilter::kPermitWindscribeApps) {
            return {DnsLeakFilter::kBlockAll, true};
        }
        return {current, false};
    case CONNECT_STATE_DISCONNECTING:
        // The tunnel is going away; a reconnect may follow before the next CONNECTING.
        if (current == DnsLeakFilter::kBlockAll) {
            return {DnsLeakFilter::kPermitWindscribeApps, true};
        }
        return {current, false};
    case CONNECT_STATE_DISCONNECTED:
        // Final disconnect, error or sleep; a reconnect does not pass through here.
        if (current == DnsLeakFilter::kOff) {
            return {current, false};
        }
        if (keepAfterSession) {
            return {DnsLeakFilter::kPermitWindscribeApps, current != DnsLeakFilter::kPermitWindscribeApps};
        }
        return {DnsLeakFilter::kOff, true};
    }
    return {current, false};
}

DnsLeakFilterStep proxiedDnsLeakFilterOnNetworkChange(DnsLeakFilter current)
{
    return {current, current != DnsLeakFilter::kOff};
}

DnsLeakFilterStep proxiedDnsLeakFilterAfterFirewallOff(DnsLeakFilter current, CONNECT_STATE state)
{
    // During a session the filter follows the session (the Automatic firewall can go off once connected).
    if (state == CONNECT_STATE_DISCONNECTED && current != DnsLeakFilter::kOff) {
        return {DnsLeakFilter::kOff, true};
    }
    return {current, false};
}

} // namespace firewall_policy
