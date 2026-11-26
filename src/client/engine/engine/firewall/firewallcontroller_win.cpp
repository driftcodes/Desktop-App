#include "firewallcontroller_win.h"

#include <QStringList>

#include "utils/log/categories.h"

FirewallController_win::FirewallController_win(QObject *parent, Helper *helper) : FirewallController(parent),
    helper_(helper)
{
}

FirewallController_win::~FirewallController_win()
{
}

void FirewallController_win::firewallOn(const QString &connectingIp, const QSet<QString> &ips, bool bAllowLanTraffic, bool bIsCustomConfig, bool isVpnConnected,
                                        const QSet<QString> &windscribeOnlyIps)
{
    QMutexLocker locker(&mutex_);
    FirewallController::firewallOn(connectingIp, ips, bAllowLanTraffic, bIsCustomConfig, isVpnConnected, windscribeOnlyIps);
    bool isApplied = true;
    if (isStateChanged())
    {
        qCInfo(LOG_FIREWALL_CONTROLLER) << "firewall enabled with ips count:" << ips.count()
                                        << "Windscribe-only ips count:" << windscribeOnlyIps.count();
        isApplied = helper_->firewallOn(connectingIp, QStringList(ips.begin(), ips.end()),
                                        QStringList(windscribeOnlyIps.begin(), windscribeOnlyIps.end()), bAllowLanTraffic, bIsCustomConfig);
        isLastApplyComplete_ = isApplied;
        if (!isApplied) {
            // The firewall is on (blocking more, not less), but e.g. the DNS servers Windscribe needs
            // to reconnect through the proxy may not be permitted. Not committing makes the next
            // firewall update send it again; the helper re-detects Windscribe's programs then.
            qCCritical(LOG_FIREWALL_CONTROLLER) << "firewall is on, but the helper could not apply it completely"
                                                << "(DNS baseline, or a permit; Windscribe-only ips count:" << windscribeOnlyIps.count()
                                                << "); connections are held and it is retried";
        }
    }
    if (isApplied) {
        commitFirewallOn(connectingIp, ips, bAllowLanTraffic, bIsCustomConfig, isVpnConnected, windscribeOnlyIps);
    }
}

bool FirewallController_win::isFirewallComplete() const
{
    QMutexLocker locker(&mutex_);
    return isLastApplyComplete_;
}

void FirewallController_win::firewallOff()
{
    QMutexLocker locker(&mutex_);
    FirewallController::firewallOff();
    if (isStateChanged())
    {
        qCInfo(LOG_FIREWALL_CONTROLLER) << "firewall disabled";
        helper_->firewallOff();
        isLastApplyComplete_ = true;
    }
    commitFirewallOff();
}

bool FirewallController_win::firewallActualState()
{
    QMutexLocker locker(&mutex_);
    return helper_->firewallActualState();
}

bool FirewallController_win::whitelistPorts(const api_responses::StaticIpPortsVector &ports)
{
    QMutexLocker locker(&mutex_);
    return helper_->whitelistPorts(ports.getAsStringWithDelimiters());
}

bool FirewallController_win::deleteWhitelistPorts()
{
    QMutexLocker locker(&mutex_);
    return helper_->deleteWhitelistPorts();
}

void FirewallController_win::setVpnInterface_posix(const QString &vpnInterface)
{
    Q_UNUSED(vpnInterface);
    //nothing todo for Windows
}

void FirewallController_win::setFirewallOnBoot(bool bEnable, const QSet<QString> &ipTable, bool isAllowLanTraffic)
{
    // On Windows firewall on boot just retains existing firewall if enabled
    if (!helper_->setFirewallOnBoot(bEnable)) {
        // The helper keeps retrying the write; until it succeeds a reboot follows the old setting.
        qCCritical(LOG_FIREWALL_CONTROLLER) << "The Always On setting (" << bEnable << ") could not be saved yet; the helper retries";
    }
}
