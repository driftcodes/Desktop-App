#pragma once

#include "iconnectionattemptstrategy.h"
#include "engine/locationsmodel/customconfiglocationinfo.h"

// // manage manual connection mode (only for API and static ips locations)
class CustomConfigConnectionAttemptStrategy : public IConnectionAttemptStrategy
{
    Q_OBJECT
public:
    // tcpOnly: a proxy is configured, so only the profile's TCP remotes may be dialed (OpenVPN can
    // carry only TCP through a proxy). UDP remotes are skipped; a profile with none is refused later.
    explicit CustomConfigConnectionAttemptStrategy(QSharedPointer<locationsmodel::BaseLocationInfo> bli, bool tcpOnly = false);


    void reset() override;
    void debugLocationInfoToLog() const override;
    void putFailedConnection() override;
    bool isFailed() const override;
    CurrentConnectionDescr getCurrentConnectionSettings() const override;
    bool isAutomaticMode() override;
    void resolveHostnames() override;
    types::Protocol preResolveProtocol() const override;
    bool usesConnectTimeout() const override { return false; }
    bool surfacesTunnelTestFailure() const override { return true; }

private slots:
    void onLocationHostnamesResolved();

private:
    QSharedPointer<locationsmodel::CustomConfigLocationInfo> locationInfo_;
    const bool tcpOnly_;

    void skipToTcpNodeIfRequired();
    bool hasNoProxyUsableRemote() const;
};
