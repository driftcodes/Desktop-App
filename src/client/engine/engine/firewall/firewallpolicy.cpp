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

ProxiedDnsLeakFilter::ProxiedDnsLeakFilter(Send send, ScheduleRetry scheduleRetry)
    : send_(std::move(send)), scheduleRetry_(std::move(scheduleRetry))
{
}

void ProxiedDnsLeakFilter::onConnectState(CONNECT_STATE state, bool isProxySet, bool keepAfterSession)
{
    const DnsLeakFilterStep step = proxiedDnsLeakFilter(wanted_, state, isProxySet, keepAfterSession);
    if (state == CONNECT_STATE_CONNECTING && step.next == DnsLeakFilter::kOff) {
        // A session without a proxy: its connector manages the filter itself. A pending retry (say, of
        // a failed disable after the previous proxied session) must not turn off what it enables, and
        // nothing confirmed before still holds: the connector removes the filter when it ends.
        ++token_;
        confirmed_ = DnsLeakFilter::kOff;
    }
    apply(step);
}

void ProxiedDnsLeakFilter::onNetworkChange()
{
    apply(proxiedDnsLeakFilterOnNetworkChange(wanted_));
}

void ProxiedDnsLeakFilter::onFirewallOff(CONNECT_STATE state)
{
    apply(proxiedDnsLeakFilterAfterFirewallOff(wanted_, state));
}

void ProxiedDnsLeakFilter::onShutdown()
{
    apply({DnsLeakFilter::kOff, wanted_ != DnsLeakFilter::kOff});
    ++token_;  // nothing is retried after shutdown
}

void ProxiedDnsLeakFilter::onRetry(quint64 token)
{
    if (token == token_) {
        send();
    }
}

bool ProxiedDnsLeakFilter::mayConnect()
{
    if (wanted_ == DnsLeakFilter::kOff || confirmed_ == wanted_) {
        return true;
    }
    send();
    return confirmed_ == wanted_;
}

bool ProxiedDnsLeakFilter::mayStartAttempt()
{
    if (wanted_ == DnsLeakFilter::kBlockAll) {
        // The connection manager retries before the engine has seen the reconnect.
        wanted_ = DnsLeakFilter::kPermitWindscribeApps;
        retryDelayMs_ = kFirstRetryMs;
        send();
    }
    return mayConnect();
}

void ProxiedDnsLeakFilter::apply(const DnsLeakFilterStep &step)
{
    if (!step.apply) {
        wanted_ = step.next;
        return;
    }
    wanted_ = step.next;
    retryDelayMs_ = kFirstRetryMs;
    send();
}

void ProxiedDnsLeakFilter::send()
{
    ++token_;  // supersedes any retry already scheduled
    const DnsLeakFilterSendResult result = send_(wanted_);
    if (wanted_ == DnsLeakFilter::kOff) {
        if (result == DnsLeakFilterSendResult::kApplied) {
            confirmed_ = DnsLeakFilter::kOff;
            retryDelayMs_ = kFirstRetryMs;
            return;
        }
    } else {
        // The wanted rules' blocks are in place unless it failed; a failure keeps the previous rules,
        // so confirmed_ keeps naming them.
        if (result != DnsLeakFilterSendResult::kFailed) {
            confirmed_ = wanted_;
        }
        if (result == DnsLeakFilterSendResult::kApplied) {
            retryDelayMs_ = kFirstRetryMs;
            return;
        }
    }
    scheduleRetry_(token_, retryDelayMs_);
    retryDelayMs_ = qMin(retryDelayMs_ * 2, kMaxRetryMs);
}

} // namespace firewall_policy
