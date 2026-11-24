#include "ovpnroutingpolicy.h"

#include <QtGlobal>
#include <algorithm>
#include <utility>

namespace customconfigs {

namespace {

QString directiveName(const QStringList &tokens)
{
    if (tokens.isEmpty()) {
        return QString();
    }
    QString name = tokens.first();
    // Config files also accept the command-line spelling.
    if (name.startsWith("--")) {
        name.remove(0, 2);
    }
    return name;
}

bool isRouteOption(const QString &name)
{
    return name == "redirect-gateway" || name == "redirect-private" || name == "route";
}

// Applies one redirect-gateway / redirect-private option the way OpenVPN's add_option() does.
void applyRedirectOption(const QStringList &tokens, bool &redirectIpv4)
{
    const QString name = directiveName(tokens);
    if (tokens.contains("!ipv4")) {
        redirectIpv4 = false;
    } else if (name == "redirect-gateway") {
        redirectIpv4 = true;
    }
}

OvpnRoute routeFromTokens(const QStringList &tokens)
{
    return OvpnRoute{tokens.value(1), tokens.value(2), tokens.value(3)};
}

bool parseIpv4(const QString &text, quint32 &out)
{
    const QStringList parts = text.split('.');
    if (parts.size() != 4) {
        return false;
    }
    quint32 value = 0;
    for (const QString &part : parts) {
        bool ok = false;
        const uint octet = part.toUInt(&ok);
        if (!ok || octet > 255 || part.isEmpty()) {
            return false;
        }
        value = (value << 8) | octet;
    }
    out = value;
    return true;
}

// A netmask: contiguous ones from the top.
bool parseNetmask(const QString &text, quint32 &out)
{
    quint32 mask = 0;
    if (!parseIpv4(text, mask)) {
        return false;
    }
    const quint32 inverted = ~mask;
    if ((inverted & (inverted + 1)) != 0) {
        return false;
    }
    out = mask;
    return true;
}

} // namespace

QStringList tokenizeOvpnLine(const QString &line)
{
    QStringList tokens;
    QString current;
    bool inToken = false;
    QChar quote;
    for (int i = 0; i < line.size(); ++i) {
        const QChar c = line[i];
        if (!quote.isNull()) {
            if (c == quote) {
                quote = QChar();
            } else if (quote == '"' && c == '\\' && i + 1 < line.size()) {
                current += line[++i];
            } else {
                current += c;
            }
            continue;
        }
        if (c.isSpace()) {
            if (inToken) {
                tokens << current;
                current.clear();
                inToken = false;
            }
            continue;
        }
        if (!inToken && (c == '#' || c == ';')) {
            break;
        }
        inToken = true;
        if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '\\' && i + 1 < line.size()) {
            current += line[++i];
        } else {
            current += c;
        }
    }
    if (inToken) {
        tokens << current;
    }
    return tokens;
}

bool hasLoopbackWrapperRemote(const QString &config)
{
    const QStringList lines = config.split('\n');
    for (const QString &line : lines) {
        const QStringList tokens = tokenizeOvpnLine(line);
        if (directiveName(tokens) == "remote" && tokens.value(1) == "127.0.0.1") {
            return true;
        }
    }
    return false;
}

bool OvpnRoutingPolicy::isPushedOptionAccepted(const QString &option) const
{
    if (routeNopull && isRouteOption(directiveName(tokenizeOvpnLine(option)))) {
        return false;
    }
    for (const OvpnPullFilter &filter : pullFilters) {
        if (option.startsWith(filter.text, Qt::CaseSensitive)) {
            return filter.action == "accept";
        }
    }
    return true;
}

bool OvpnRoutingPolicy::sendsAllIpv4ThroughTunnel(const QStringList &pushedOptions) const
{
    bool redirectIpv4 = redirectsIpv4Locally;
    QVector<OvpnRoute> allRoutes = routes;
    QStringList ifconfigArgs = ifconfig;
    QString topologyName = topology;
    QString routeGateway;  // route-gateway in a config file is stripped by the helper; only a push sets it

    for (const QString &rawOption : pushedOptions) {
        const QString option = rawOption.trimmed();
        const QStringList tokens = tokenizeOvpnLine(option);
        const QString name = directiveName(tokens);
        if (name.isEmpty() || !isPushedOptionAccepted(option)) {
            continue;
        }
        if (name == "redirect-gateway" || name == "redirect-private") {
            applyRedirectOption(tokens, redirectIpv4);
        } else if (name == "route") {
            allRoutes << routeFromTokens(tokens);
        } else if (name == "route-gateway") {
            routeGateway = tokens.value(1);
        } else if (name == "ifconfig") {
            ifconfigArgs = tokens.mid(1);
        } else if (name == "topology") {
            topologyName = tokens.value(1);
        }
    }

    if (redirectIpv4) {
        return true;
    }

    // The VPN gateway (OpenVPN's remote_endpoint) and the tunnel's own subnet.
    quint32 endpoint = 0;
    bool hasEndpoint = parseIpv4(routeGateway, endpoint);
    quint32 subnetMask = 0;
    quint32 subnetNetwork = 0;
    bool hasSubnet = false;
    quint32 local = 0;
    if (ifconfigArgs.size() >= 2 && parseIpv4(ifconfigArgs[0], local)) {
        quint32 mask = 0;
        const bool secondIsNetmask = topologyName == "subnet" ||
            (topologyName.isEmpty() && parseNetmask(ifconfigArgs[1], mask) && (mask >> 24) == 0xFF);
        if (secondIsNetmask) {
            if (parseNetmask(ifconfigArgs[1], mask)) {
                subnetMask = mask;
                subnetNetwork = local & mask;
                hasSubnet = true;
            }
        } else if (!hasEndpoint) {
            hasEndpoint = parseIpv4(ifconfigArgs[1], endpoint);
        }
    }

    auto isTunnelGateway = [&](const QString &gateway) {
        if (gateway.isEmpty() || gateway == "default" || gateway == "vpn_gateway") {
            return true;
        }
        quint32 address = 0;
        if (!parseIpv4(gateway, address)) {
            return false;  // net_gateway, remote_host or a hostname
        }
        return (hasEndpoint && address == endpoint) || (hasSubnet && (address & subnetMask) == subnetNetwork);
    };

    // Whether the routes through the tunnel cover all of 0.0.0.0-255.255.255.255.
    QVector<std::pair<quint64, quint64>> ranges;
    for (const OvpnRoute &route : std::as_const(allRoutes)) {
        if (!isTunnelGateway(route.gateway)) {
            continue;
        }
        quint32 network = 0;
        quint32 mask = 0xFFFFFFFF;
        if (!parseIpv4(route.network, network)) {
            continue;
        }
        if (!route.netmask.isEmpty() && route.netmask != "default" && !parseNetmask(route.netmask, mask)) {
            continue;
        }
        const quint64 first = network & mask;
        ranges.append({first, first + static_cast<quint64>(~mask)});
    }
    std::sort(ranges.begin(), ranges.end());
    quint64 nextUncovered = 0;
    for (const auto &range : std::as_const(ranges)) {
        if (range.first > nextUncovered) {
            return false;
        }
        nextUncovered = std::max(nextUncovered, range.second + 1);
    }
    return nextUncovered > 0xFFFFFFFFull;
}

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config)
{
    OvpnRoutingPolicy policy;
    bool insideInlineBlock = false;

    const QStringList lines = config.split('\n');
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        // Inline blocks (<ca>...</ca> and the like) hold key material, never routing directives.
        if (insideInlineBlock) {
            if (trimmed.startsWith("</")) {
                insideInlineBlock = false;
            }
            continue;
        }
        if (trimmed.startsWith('<') && !trimmed.startsWith("</")) {
            insideInlineBlock = !trimmed.contains("</");
            continue;
        }

        const QStringList tokens = tokenizeOvpnLine(trimmed);
        const QString name = directiveName(tokens);
        // Only directives that reach the daemon count. The helper strips the ones not on its allowlist,
        // among them route-noexec, route-gateway and redirect-private (the patched daemon would reject
        // them anyway).
        if (name == "redirect-gateway") {
            applyRedirectOption(tokens, policy.redirectsIpv4Locally);
        } else if (name == "route") {
            policy.routes << routeFromTokens(tokens);
        } else if (name == "ifconfig") {
            policy.ifconfig = tokens.mid(1);
        } else if (name == "topology") {
            policy.topology = tokens.value(1);
        } else if (name == "route-nopull") {
            policy.routeNopull = true;
        } else if (name == "pull-filter" && tokens.size() >= 3) {
            policy.pullFilters.append(OvpnPullFilter{tokens[1], tokens[2]});
        }
    }

#ifdef Q_OS_WIN
    // For a config that dials a local wrapper (stunnel/wstunnel), the Windows helper appends
    // "--pull-filter ignore redirect-gateway --route 0.0.0.0 128.0.0.0 vpn_gateway
    // --route 128.0.0.0 128.0.0.0 vpn_gateway" after the config (openvpncontroller.cpp).
    if (hasLoopbackWrapperRemote(config)) {
        policy.pullFilters.append(OvpnPullFilter{"ignore", "redirect-gateway"});
        policy.routes << OvpnRoute{"0.0.0.0", "128.0.0.0", "vpn_gateway"} << OvpnRoute{"128.0.0.0", "128.0.0.0", "vpn_gateway"};
    }
#endif
    return policy;
}

QStringList pushReplyOptions(const QString &managementLine)
{
    const int firstQuote = managementLine.indexOf('\'');
    const int lastQuote = managementLine.lastIndexOf('\'');
    if (firstQuote == -1 || lastQuote <= firstQuote) {
        return QStringList();
    }
    QStringList options = managementLine.mid(firstQuote + 1, lastQuote - firstQuote - 1).split(',');
    if (!options.isEmpty() && options.first().trimmed() == "PUSH_REPLY") {
        options.removeFirst();
    }
    return options;
}

} // namespace customconfigs
