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

DnsLeakFilterStep proxiedDnsLeakFilter(DnsLeakFilter current, CONNECT_STATE state, bool isProxySet, bool keepAfterSession,
                                       bool isNewSession)
{
    switch (state) {
    case CONNECT_STATE_CONNECTING:
        // Entered once per connect or reconnect: the state controller does not repeat CONNECTING for
        // further attempts, so network changes are handled by proxiedDnsLeakFilterOnNetworkChange.
        if (!isProxySet) {
            if (!isEnginesDnsLeakFilter(current)) {
                return {current, false};
            }
            if (isNewSession) {
                // A new session without a proxy: its connector manages the filter. Hand over the one
                // kept after the previous proxied session, rules left in place for the connector.
                return {DnsLeakFilter::kHandedOver, true};
            }
            // A proxied session reconnecting after the proxy was turned off keeps the filter.
        }
        return {DnsLeakFilter::kPermitWindscribeApps, true};
    case CONNECT_STATE_CONNECTED:
        if (current == DnsLeakFilter::kPermitWindscribeApps) {
            return {DnsLeakFilter::kBlockAll, true};
        }
        // kHandedOver stays until the session is over: if the connector has not taken the rules over,
        // they are the only filter there is.
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
        if (keepAfterSession && isEnginesDnsLeakFilter(current)) {
            return {DnsLeakFilter::kPermitWindscribeApps, current != DnsLeakFilter::kPermitWindscribeApps};
        }
        return {DnsLeakFilter::kOff, true};
    }
    return {current, false};
}

DnsLeakFilterStep proxiedDnsLeakFilterOnNetworkChange(DnsLeakFilter current)
{
    return {current, isEnginesDnsLeakFilter(current)};
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
    const bool isNewSession = state == CONNECT_STATE_CONNECTING && lastState_ == CONNECT_STATE_DISCONNECTED;
    lastState_ = state;
    if (state == CONNECT_STATE_DISCONNECTED && wanted_ == DnsLeakFilter::kHandedOver &&
        isEnginesDnsLeakFilter(confirmed_)) {
        // The hand-over never reached the helper (the direct attempt was held for it): the engine
        // still holds its rules. Treat them as such, so an error with the firewall on keeps them
        // instead of removing the only DNS filter there is. The pending hand-over is dropped.
        ++token_;
        wanted_ = confirmed_;
    }
    const DnsLeakFilterStep step = proxiedDnsLeakFilter(wanted_, state, isProxySet, keepAfterSession, isNewSession);
    if (state == CONNECT_STATE_CONNECTING && !isEnginesDnsLeakFilter(step.next)) {
        // A session without a proxy: its connector manages the filter itself. A pending retry (say, of
        // a failed disable after the previous proxied session) must not turn off what it enables.
        ++token_;
        if (step.next == DnsLeakFilter::kOff) {
            // Nothing confirmed before still holds: the connector removes the filter when it ends.
            confirmed_ = DnsLeakFilter::kOff;
        }
        // kHandedOver: the engine's rules stay confirmed until the helper confirms the hand-over.
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

void ProxiedDnsLeakFilter::claimForProxiedRequest(bool isProxied)
{
    if (isProxied && !isEnginesDnsLeakFilter(wanted_)) {
        // E.g. the proxy turned on and another location picked while an attempt without it was still
        // CONNECTING: no CONNECTING arrives for the replacement, and its OpenVPN leaves the filter to
        // the engine. The previous connector's teardown is then ignored by the helper.
        wanted_ = DnsLeakFilter::kPermitWindscribeApps;
        retryDelayMs_ = kFirstRetryMs;
        send();
    }
}

void ProxiedDnsLeakFilter::onConnectRequest(bool isProxied, bool isPreviousSessionActive)
{
    if (isProxied) {
        claimForProxiedRequest(true);
    } else if (isEnginesDnsLeakFilter(wanted_) && !isPreviousSessionActive) {
        // Hand-over without removal: the connector replaces the rules when it starts. The helper
        // ignores this engine's retries once the connector holds the filter. confirmed_ keeps naming
        // the engine's rules until the helper confirms the hand-over.
        ++token_;
        apply({DnsLeakFilter::kHandedOver, true});
    }
}

bool ProxiedDnsLeakFilter::mayConnect(bool isProxied)
{
    claimForProxiedRequest(isProxied);
    // kOff: not the engine's. Otherwise the helper must have confirmed it: the engine's rules, or the
    // hand-over (the connector's rules would be ignored while the helper still sees the engine).
    if (wanted_ == DnsLeakFilter::kOff || confirmed_ == wanted_) {
        return true;
    }
    send();
    return confirmed_ == wanted_;
}

bool ProxiedDnsLeakFilter::mayStartAttempt(bool isProxied)
{
    claimForProxiedRequest(isProxied);
    if (wanted_ == DnsLeakFilter::kBlockAll) {
        // The connection manager retries before the engine has seen the reconnect.
        wanted_ = DnsLeakFilter::kPermitWindscribeApps;
        retryDelayMs_ = kFirstRetryMs;
        send();
    }
    return mayConnect(isProxied);
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
    if (!isEnginesDnsLeakFilter(wanted_)) {
        if (result == DnsLeakFilterSendResult::kApplied) {
            confirmed_ = wanted_;  // kOff, or kHandedOver: the helper let go
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
