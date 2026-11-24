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

// What an OpenVPN config says about IPv4 default-gateway redirection, read from its text, plus the
// rules OpenVPN uses to combine it with what the server pushes (options.c, OpenVPN 2.7):
// redirect-gateway / redirect-private flags accumulate across the config and the push, and "!ipv4"
// in any of them switches IPv4 redirection off again.
struct OvpnRoutingPolicy
{
    // IPv4 redirection after the config's own redirect-gateway / redirect-private lines, in order.
    bool redirectsIpv4Locally = false;
    // The config routes 0.0.0.0/1 and 128.0.0.0/1 (or 0.0.0.0/0) into the tunnel itself.
    bool hasLowerHalfRoute = false;
    bool hasUpperHalfRoute = false;
    // route-nopull: pushed routes and redirect-gateway are dropped.
    bool routeNopull = false;
    // route-noexec: OpenVPN installs no routes at all.
    bool routesNotExecuted = false;
    QVector<OvpnPullFilter> pullFilters;

    // Whether OpenVPN would apply this pushed option line (pull-filter and route-nopull).
    bool isPushedOptionAccepted(const QString &option) const;

    // Whether the tunnel carries all IPv4 traffic, given every option line the server pushed, in order.
    bool sendsAllIpv4ThroughTunnel(const QStringList &pushedOptions) const;

    // Before connecting, when the push is not known: false only if no ordinary redirect-gateway push
    // could make the tunnel carry all IPv4 traffic.
    bool mayRedirectAllIpv4() const;
};

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config);

// The option lines of one ">LOG:...PUSH: Received control message: 'PUSH_REPLY,a,b,...'" line,
// without the leading PUSH_REPLY. Empty if the line carries no quoted payload.
QStringList pushReplyOptions(const QString &managementLine);

// Splits one config line into OpenVPN tokens: whitespace separates, "..." (with \" and \\ escapes)
// and '...' group, and # or ; at the start of a token begins a comment.
QStringList tokenizeOvpnLine(const QString &line);

} // namespace customconfigs
