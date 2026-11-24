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

    // For a proxy on this machine (127.x / ::1). When redirect-gateway is in effect, OpenVPN adds a
    // host route sending its "remote" via the physical gateway; behind a proxy that remote is the
    // proxy address, and Windows refuses such a route for a loopback address (CONNECTED,ROUTE_ERROR).
    // Appends "redirect-private local", whose "local" flag makes OpenVPN skip exactly that host route
    // whether redirect-gateway comes from the config or from the server's push. It enables no
    // redirection by itself, so the config's routing policy is otherwise unchanged. "autolocal" is
    // dropped from the config's own redirect-gateway lines, since it can re-enable the host route.
    static void addLoopbackProxyRouteFix(QString &config);

private:
    QString config_;
};
