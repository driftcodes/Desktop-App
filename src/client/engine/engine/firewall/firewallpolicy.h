#pragma once

#include <functional>
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

} // namespace firewall_policy
