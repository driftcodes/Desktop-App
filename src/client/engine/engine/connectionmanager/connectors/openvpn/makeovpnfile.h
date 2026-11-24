#pragma once

#include "types/protocol.h"

class MakeOVPNFile
{
public:
    MakeOVPNFile();
    virtual ~MakeOVPNFile();

    bool generate(const QString &ovpnData, const QString &ip, types::Protocol protocol, uint port,
                  uint portForStunnelOrWStunnel, int mss, const QString &defaultGateway, const QString &openVpnX509,
                  const QString &customDns, bool isAntiCensorship, const QString &awgPreset);
    QString config() { return config_; }

    // Shared with the custom-config prepare path so the two DNS-override copies can't drift.
    static void appendDnsOverride(QString &config, const QString &dnsServer);

    // For a proxy on this machine (127.x / ::1). The helper passes "--redirect-private local" on the
    // OpenVPN command line so OpenVPN does not route the loopback proxy address via the physical
    // gateway (Windows refuses that route: CONNECTED,ROUTE_ERROR). The config's own redirect-gateway
    // "autolocal" flag can override "local", so it is removed here; nothing else is changed.
    static void removeAutolocalForLoopbackProxy(QString &config);

private:
    QString config_;
};
