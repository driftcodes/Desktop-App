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

// Applies one redirect-gateway / redirect-private option the way OpenVPN's add_option() does: flags
// accumulate (def1 stays once seen), and "!ipv4" clears the IPv4 redirection itself.
void applyRedirectOption(const QStringList &tokens, bool &redirectIpv4, bool &def1)
{
    const QString name = directiveName(tokens);
    if (tokens.contains("def1")) {
        def1 = true;
    }
    if (tokens.contains("!ipv4")) {
        redirectIpv4 = false;
    } else if (name == "redirect-gateway") {
        redirectIpv4 = true;
    }
}

// Calls visit(tokens) for every directive line OpenVPN reads as a directive: comments are dropped, and
// inline data blocks (<ca>, <auth-user-pass>, ...) are skipped. <connection> blocks hold directives
// (remote among them), so their lines are visited when includeConnectionBlocks is set.
template<typename Visitor>
void forEachDirective(const QString &config, bool includeConnectionBlocks, Visitor visit)
{
    QString openTag;
    const QStringList lines = config.split('\n');
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith("</")) {
            openTag.clear();
            continue;
        }
        if (trimmed.startsWith('<')) {
            const int end = trimmed.indexOf('>');
            const QString tag = trimmed.mid(1, end > 0 ? end - 1 : -1).trimmed().toLower();
            // A one-line block (<tag>...</tag>) closes on the same line.
            openTag = trimmed.contains("</") ? QString() : tag;
            continue;
        }
        if (!openTag.isEmpty() && !(includeConnectionBlocks && openTag == "connection")) {
            continue;
        }
        const QStringList tokens = tokenizeOvpnLine(trimmed);
        if (!tokens.isEmpty()) {
            visit(tokens);
        }
    }
}

// Address ranges the Windscribe firewall lets through whatever the tunnel does (LAN traffic when allowed,
// link-local, multicast), matching helper/windows/firewallfilter.cpp.
const QVector<std::pair<quint32, quint32>> &firewallExemptRanges()
{
    static const QVector<std::pair<quint32, quint32>> ranges = {
        {0x0A000000u, 0x0AFFFFFFu},  // 10.0.0.0/8
        {0xAC100000u, 0xAC1FFFFFu},  // 172.16.0.0/12
        {0xC0A80000u, 0xC0A8FFFFu},  // 192.168.0.0/16
        {0xA9FE0000u, 0xA9FEFFFFu},  // 169.254.0.0/16
        {0xE0000000u, 0xEFFFFFFFu},  // 224.0.0.0/4
    };
    return ranges;
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
    bool found = false;
    forEachDirective(config, true, [&found](const QStringList &tokens) {
        if (directiveName(tokens) == "remote" && tokens.value(1) == "127.0.0.1") {
            found = true;
        }
    });
    return found;
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
    bool def1 = redirectDef1;
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
            applyRedirectOption(tokens, redirectIpv4, def1);
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

    // Next hops inside the tunnel: the default VPN gateway (route-gateway), the ifconfig peer
    // (net30/p2p) and any address on the tunnel adapter's subnet. Windows OpenVPN puts a route with an
    // explicit gateway on the tunnel adapter when the gateway is inside that adapter's subnet, so the
    // peer is a tunnel next hop even when a different route-gateway is pushed.
    QVector<quint32> tunnelHops;
    quint32 address = 0;
    if (parseIpv4(routeGateway, address)) {
        tunnelHops << address;
    }
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
        } else if (parseIpv4(ifconfigArgs[1], address)) {
            tunnelHops << address;
            // A net30 adapter sits on the /30 holding both ends.
            subnetMask = 0xFFFFFFFCu;
            subnetNetwork = local & subnetMask;
            hasSubnet = (address & subnetMask) == subnetNetwork;
        }
    }

    auto isTunnelGateway = [&](const QString &gateway) {
        if (gateway.isEmpty() || gateway == "default" || gateway == "vpn_gateway") {
            return true;
        }
        quint32 hop = 0;
        if (!parseIpv4(gateway, hop)) {
            return false;  // net_gateway, remote_host or a hostname
        }
        return tunnelHops.contains(hop) || (hasSubnet && (hop & subnetMask) == subnetNetwork);
    };

    // Every route the daemon installs, as address ranges with their prefix length. Redirection adds
    // 0.0.0.0/1 + 128.0.0.0/1 (def1) or replaces the default route (/0) through the tunnel.
    struct RangeRoute
    {
        quint64 first;
        quint64 last;
        int prefix;
        bool tunnel;
    };
    QVector<RangeRoute> installed;
    if (redirectIpv4) {
        if (def1) {
            installed << RangeRoute{0, 0x7FFFFFFFull, 1, true} << RangeRoute{0x80000000ull, 0xFFFFFFFFull, 1, true};
        } else {
            installed << RangeRoute{0, 0xFFFFFFFFull, 0, true};
        }
    }
    for (const OvpnRoute &route : std::as_const(allRoutes)) {
        quint32 network = 0;
        quint32 mask = 0xFFFFFFFF;
        if (!parseIpv4(route.network, network)) {
            continue;
        }
        if (!route.netmask.isEmpty() && route.netmask != "default" && !parseNetmask(route.netmask, mask)) {
            continue;
        }
        const quint64 first = network & mask;
        installed << RangeRoute{first, first + static_cast<quint64>(~mask), qPopulationCount(mask), isTunnelGateway(route.gateway)};
    }

    // Addresses that may stay outside the tunnel without the firewall blocking them: its LAN /
    // link-local / multicast exceptions and the VPN server itself (always whitelisted while connecting).
    QVector<std::pair<quint64, quint64>> exempt;
    for (const auto &range : firewallExemptRanges()) {
        exempt << std::pair<quint64, quint64>(range.first, range.second);
    }
    for (const QString &remote : remoteIps) {
        if (parseIpv4(remote, address)) {
            exempt << std::pair<quint64, quint64>(address, address);
        }
    }

    // Walk the address space in pieces that no route or exemption boundary splits. Each piece goes
    // where its most specific route sends it (longest prefix; a tie counts as the tunnel). A piece
    // that leaves the tunnel, or has no route at all (the system default), must be exempt.
    QVector<quint64> bounds = {0, 0x100000000ull};
    for (const RangeRoute &route : std::as_const(installed)) {
        bounds << route.first << route.last + 1;
    }
    for (const auto &range : std::as_const(exempt)) {
        bounds << range.first << range.second + 1;
    }
    std::sort(bounds.begin(), bounds.end());
    bounds.erase(std::unique(bounds.begin(), bounds.end()), bounds.end());

    for (int i = 0; i + 1 < bounds.size(); ++i) {
        const quint64 start = bounds[i];
        int bestPrefix = -1;
        bool bestIsTunnel = false;
        for (const RangeRoute &route : std::as_const(installed)) {
            if (route.first <= start && start <= route.last) {
                if (route.prefix > bestPrefix) {
                    bestPrefix = route.prefix;
                    bestIsTunnel = route.tunnel;
                } else if (route.prefix == bestPrefix && route.tunnel) {
                    bestIsTunnel = true;
                }
            }
        }
        if (bestPrefix >= 0 && bestIsTunnel) {
            continue;
        }
        const bool isExempt = std::any_of(exempt.begin(), exempt.end(), [start](const std::pair<quint64, quint64> &range) {
            return range.first <= start && start <= range.second;
        });
        if (!isExempt) {
            return false;
        }
    }
    return true;
}

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config)
{
    OvpnRoutingPolicy policy;

    // The VPN server addresses (remote lines, <connection> blocks included).
    forEachDirective(config, true, [&policy](const QStringList &tokens) {
        if (directiveName(tokens) == "remote" && tokens.size() >= 2) {
            policy.remoteIps << tokens[1];
        }
    });

    // Routing directives are only valid at the top level.
    forEachDirective(config, false, [&policy](const QStringList &tokens) {
        const QString name = directiveName(tokens);
        // Only directives that reach the daemon count. The helper strips the ones not on its allowlist,
        // among them route-noexec, route-gateway and redirect-private (the patched daemon would reject
        // them anyway).
        if (name == "redirect-gateway") {
            applyRedirectOption(tokens, policy.redirectsIpv4Locally, policy.redirectDef1);
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
    });

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
