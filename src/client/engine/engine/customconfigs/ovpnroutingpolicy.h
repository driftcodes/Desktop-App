#pragma once

#include <QString>

namespace customconfigs {

// What an OpenVPN config itself says about IPv4 default-gateway redirection, read from its text.
// Whether the server pushes redirect-gateway is only known once connected; see sendsAllIpv4ThroughTunnel().
struct OvpnRoutingPolicy
{
    // The config routes all IPv4 into the tunnel on its own: a redirect-gateway line without "!ipv4",
    // a "route 0.0.0.0 0.0.0.0" line, or both halves "route 0.0.0.0 128.0.0.0" and
    // "route 128.0.0.0 128.0.0.0", each via the tunnel (no gateway, or vpn_gateway).
    bool redirectsIpv4Locally = false;
    // A pushed redirect-gateway is dropped: route-nopull, or a matching "pull-filter ignore|reject".
    bool ignoresPushedRedirect = false;
    // route-noexec: OpenVPN installs no routes at all.
    bool routesNotExecuted = false;

    // Whether the tunnel will carry all IPv4 traffic, given whether the server pushed redirect-gateway.
    bool sendsAllIpv4ThroughTunnel(bool serverPushedRedirect) const
    {
        if (routesNotExecuted) {
            return false;
        }
        return redirectsIpv4Locally || (serverPushedRedirect && !ignoresPushedRedirect);
    }

    // Before connecting, when the push is not known yet: false only if no push could make it full-tunnel.
    bool mayRedirectAllIpv4() const { return sendsAllIpv4ThroughTunnel(true); }
};

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config);

} // namespace customconfigs
