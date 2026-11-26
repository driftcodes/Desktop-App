#pragma once

#include <QObject>
#include <QSet>
#include "api_responses/staticips.h"

class IHelper;

// basic class FirewallController
// implement state changes logic
class FirewallController : public QObject
{
    Q_OBJECT
public:
    explicit FirewallController(QObject *parent);
    virtual ~FirewallController() {}

    // this function also uses for change firewall ips, then it is already enabled.
    // windscribeOnlyIps: addresses permitted only for Windscribe's own programs (Windows: the client,
    // its bundled tools, ctrld and the helper service), not for every program like ips. Only the
    // Windows controller uses it; elsewhere it is empty.
    virtual void firewallOn(const QString &connectingIp, const QSet<QString> &ips, bool bAllowLanTraffic, bool bIsCustomConfig,
                            bool isVpnConnected, const QSet<QString> &windscribeOnlyIps = QSet<QString>());
    virtual void firewallOff();
    virtual bool firewallActualState() = 0;
    // Whether the helper applied the last firewallOn completely (Windows: including the DNS baseline
    // that keeps DNS off the LAN). An incomplete one is not committed, so the next update resends it.
    virtual bool isFirewallComplete() const { return true; }
    // Whether the firewall was last asked to be on (by firewallOn) rather than off: tells a firewall
    // that is intentionally off from one that should be on but is not (or whose state is unknown).
    bool isFirewallWanted() const { return isWanted_; }
    // Whether the last firewallOn that was applied successfully (committed) was the connected-state
    // one: a complete connecting-state firewall does not count for reporting connected.
    bool isConnectedStateCommitted() const { return bInitialized_ && latestEnabledState_ && latestIsVpnConnected_; }

    virtual bool whitelistPorts(const api_responses::StaticIpPortsVector &ports);
    virtual bool deleteWhitelistPorts();

    // Mac/Linux specific functions
    virtual void setVpnInterface_posix(const QString &vpnInterface) = 0;
    virtual void setFirewallOnBoot(bool bEnable, const QSet<QString>& ipTable = QSet<QString>(), bool isAllowLanTraffic = false) = 0;

protected:
    bool isStateChanged();

    // firewallOn()/firewallOff() only evaluate whether the desired state differs from the last
    // SUCCESSFULLY applied state; they no longer latch it. Platform subclasses call these commit
    // helpers after the apply actually succeeds, so a failed apply can't poison the change-detection
    // baseline — the next call still sees a change and retries instead of short-circuiting.
    void commitFirewallOn(const QString &connectingIp, const QSet<QString> &ips, bool bAllowLanTraffic, bool bIsCustomConfig, bool isVpnConnected,
                          const QSet<QString> &windscribeOnlyIps = QSet<QString>());
    void commitFirewallOff();

    QString latestConnectingIp_;
    QSet<QString> latestIps_;
    QSet<QString> latestWindscribeOnlyIps_;
    bool latestAllowLanTraffic_;
    bool latestIsCustomConfig_;
    bool latestEnabledState_;
    bool latestIsVpnConnected_;
    api_responses::StaticIpPortsVector latestStaticIpPorts_;
    bool bInitialized_;
    bool bStateChanged_;
    bool isWanted_ = false;
};
