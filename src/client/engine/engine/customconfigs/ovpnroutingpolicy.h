#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

namespace customconfigs {

// One "pull-filter accept|ignore|reject <text>" line. OpenVPN applies the first rule whose text is a
// prefix (case-sensitive) of a pushed option line.
struct OvpnPullFilter
{
    QString action;
    QString text;
};

// One "route <network> [netmask] [gateway]" line, as written.
struct OvpnRoute
{
    QString network;
    QString netmask;   // empty: 255.255.255.255
    QString gateway;   // empty: the VPN gateway
};

// What an OpenVPN config says about IPv4 routing, as the daemon receives it (after the helper's
// directive filter and with the routes the helper adds), plus the rules OpenVPN uses to combine it
// with what the server pushes (options.c, route.c, init.c; OpenVPN 2.7):
// - redirect-gateway / redirect-private flags accumulate across the config and the push, and "!ipv4"
//   in any of them switches IPv4 redirection off again;
// - a route with no gateway, "default" or vpn_gateway uses the VPN gateway: route-gateway if given,
//   otherwise the ifconfig peer for net30/p2p topologies.
struct OvpnRoutingPolicy
{
    // IPv4 redirection after the config's own redirect-gateway lines, in order, and whether one of
    // them asked for def1 (0.0.0.0/1 + 128.0.0.0/1 instead of replacing the default route).
    bool redirectsIpv4Locally = false;
    bool redirectDef1 = false;
    // The addresses of the config's remote lines: the firewall lets traffic to the VPN server through.
    QStringList remoteIps;
    QVector<OvpnRoute> routes;
    QStringList ifconfig;        // the config's own "ifconfig <local> <remote|netmask>" arguments
    QString topology;            // the config's own topology, empty if not given
    // route-nopull: pushed routes and redirect-gateway are dropped.
    bool routeNopull = false;
    QVector<OvpnPullFilter> pullFilters;

    // Whether OpenVPN would apply this pushed option line (pull-filter and route-nopull).
    bool isPushedOptionAccepted(const QString &option) const;

    // Whether the tunnel carries all IPv4 traffic the firewall would otherwise block, given every option
    // line the server pushed, in order. Every address goes where its most specific route sends it; an
    // address may leave the tunnel only if the firewall exempts it anyway (LAN, link-local, multicast,
    // the VPN server).
    bool sendsAllIpv4ThroughTunnel(const QStringList &pushedOptions) const;
};

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config);

// The option lines of one ">LOG:...PUSH: Received control message: 'PUSH_REPLY,a,b,...'" line,
// without the leading PUSH_REPLY. Empty if the line carries no quoted payload.
QStringList pushReplyOptions(const QString &managementLine);

// Splits one config line into OpenVPN tokens: whitespace separates, "..." (with \" and \\ escapes)
// and '...' group, and # or ; at the start of a token begins a comment.
QStringList tokenizeOvpnLine(const QString &line);

// Whether the config dials a local wrapper: an actual "remote 127.0.0.1" directive (the same rule as
// the helper's OvpnDirectiveWhitelist::hasLoopbackWrapperRemote). On Windows the helper then adds
// 0.0.0.0/1 and 128.0.0.0/1 through the tunnel.
bool hasLoopbackWrapperRemote(const QString &config);

} // namespace customconfigs
