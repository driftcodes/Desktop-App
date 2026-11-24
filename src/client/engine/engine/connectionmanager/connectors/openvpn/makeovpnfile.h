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

    // For a proxy on this machine (127.x / ::1). OpenVPN's redirect-gateway adds a host route that
    // sends the "remote" (which, behind an HTTP/SOCKS proxy, is the proxy address) via the physical
    // gateway; Windows refuses that route for a loopback address and OpenVPN reports
    // CONNECTED,ROUTE_ERROR. This replaces redirect-gateway with the two /1 routes it would have added,
    // without the host route: ignores a pushed redirect-gateway, drops one written in the config, and
    // routes 0.0.0.0/1 and 128.0.0.0/1 into the tunnel. A config that opts out of default-gateway
    // redirection (route-nopull, route-noexec or its own "pull-filter ignore redirect-gateway") is left
    // untouched, since OpenVPN then adds no host route either. Returns true when the config was changed.
    static bool applyLoopbackProxyRouteFix(QString &config);

private:
    QString config_;
};
