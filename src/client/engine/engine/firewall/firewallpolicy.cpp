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
                     const std::function<QSet<QString>()> &notConnectedIps, bool allowLanTraffic, bool isCustomConfig)
{
    exceptions.clearConnectionExceptions();
    if (controller.firewallActualState()) {
        controller.firewallOn(exceptions.connectingIp(), notConnectedIps(), allowLanTraffic, isCustomConfig, false);
    }
}

} // namespace firewall_policy
