#include "customconfigconnectionattemptstrategy.h"
#include "utils/ws_assert.h"
#include "utils/log/logger.h"

CustomConfigConnectionAttemptStrategy::CustomConfigConnectionAttemptStrategy(
    QSharedPointer<locationsmodel::BaseLocationInfo> bli, bool tcpOnly) :
        locationInfo_(qSharedPointerDynamicCast<locationsmodel::CustomConfigLocationInfo>(bli)),
        tcpOnly_(tcpOnly)
{
    WS_ASSERT(!locationInfo_.isNull());
    WS_ASSERT(locationInfo_->locationId().isCustomConfigsLocation());
    connect(locationInfo_.data(), &locationsmodel::CustomConfigLocationInfo::hostnamesResolved, this, &CustomConfigConnectionAttemptStrategy::onLocationHostnamesResolved);
}

void CustomConfigConnectionAttemptStrategy::onLocationHostnamesResolved()
{
    skipToTcpNodeIfRequired();
    emit hostnamesResolved();
}

void CustomConfigConnectionAttemptStrategy::skipToTcpNodeIfRequired()
{
    if (!tcpOnly_ || locationInfo_->configType() != CUSTOM_CONFIG_OPENVPN) {
        return;
    }
    // When no remote is TCP the selection stays on a UDP node, and ConnectionManager refuses the
    // attempt with kProxyRequiresTcp instead of dialing it directly.
    if (!locationInfo_->selectNodeWithProtocol("tcp")) {
        qCWarning(LOG_CONNECTION) << "A proxy is configured but this custom config has no TCP remote";
    }
}

void CustomConfigConnectionAttemptStrategy::reset()
{
    // nothing todo
}

void CustomConfigConnectionAttemptStrategy::debugLocationInfoToLog() const
{
    qCInfo(LOG_CONNECTION) << locationInfo_->getLogString();
}

void CustomConfigConnectionAttemptStrategy::putFailedConnection()
{
    // No endpoint was selected (nor resolved) for a config the proxy cannot use.
    if (hasNoProxyUsableRemote()) {
        return;
    }
    locationInfo_->selectNextNode();
    skipToTcpNodeIfRequired();
}

bool CustomConfigConnectionAttemptStrategy::isFailed() const
{
    return false;
}

bool CustomConfigConnectionAttemptStrategy::hasNoProxyUsableRemote() const
{
    return tcpOnly_ && !locationInfo_->hasRemoteWithProtocol("tcp");
}

CurrentConnectionDescr CustomConfigConnectionAttemptStrategy::getCurrentConnectionSettings() const
{
    CurrentConnectionDescr ccd;

    // A proxy is set and nothing in this config can use it (UDP-only OpenVPN, or WireGuard): report
    // the config's protocol without any endpoint, so ConnectionManager refuses with kProxyRequiresTcp
    // before anything is resolved or dialed.
    if (hasNoProxyUsableRemote()) {
        ccd.connectionNodeType = CONNECTION_NODE_CUSTOM_CONFIG;
        ccd.protocol = locationInfo_->configType() == CUSTOM_CONFIG_WIREGUARD ? types::Protocol::WIREGUARD
                                                                               : types::Protocol::OPENVPN_UDP;
        return ccd;
    }

    if (locationInfo_->isExistSelectedNode()) {
        ccd.connectionNodeType = CONNECTION_NODE_CUSTOM_CONFIG;
        ccd.ip = locationInfo_->getSelectedIp();
        ccd.port = locationInfo_->getSelectedPort();
        ccd.protocol = types::Protocol::fromString(locationInfo_->getSelectedProtocol());
        if (ccd.protocol.isWireGuardProtocol()) {
            ccd.wireGuard.customConfig = locationInfo_->getWireguardCustomConfig(ccd.ip);
        } else {
            ccd.openVpn.customConfig = locationInfo_->getOvpnConfigForSelectedEndpoint();
        }
    } else {
        ccd.connectionNodeType = CONNECTION_NODE_ERROR;
    }

    return ccd;
}

bool CustomConfigConnectionAttemptStrategy::isAutomaticMode()
{
    return false;
}

void CustomConfigConnectionAttemptStrategy::resolveHostnames()
{
    if (hasNoProxyUsableRemote()) {
        // Nothing to dial through the proxy: do not look any hostname up directly.
        emit hostnamesResolved();
        return;
    }
    // Under a proxy only the TCP remotes are kept and looked up.
    locationInfo_->resolveHostnames(tcpOnly_ ? QString("tcp") : QString());
}

types::Protocol CustomConfigConnectionAttemptStrategy::preResolveProtocol() const
{
    if (locationInfo_->configType() == CUSTOM_CONFIG_WIREGUARD) {
        return types::Protocol::WIREGUARD;
    }
    return types::Protocol::OPENVPN_UDP;
}
