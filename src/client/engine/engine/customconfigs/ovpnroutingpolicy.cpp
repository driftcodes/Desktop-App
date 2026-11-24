#include "ovpnroutingpolicy.h"

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

// A "route" that sends traffic into the tunnel: no gateway given, "default" (which OpenVPN treats as
// not given, i.e. the VPN gateway), or vpn_gateway.
bool isTunnelRoute(const QStringList &tokens, const QString &network, const QString &netmask)
{
    if (tokens.size() < 3 || tokens[1] != network || tokens[2] != netmask) {
        return false;
    }
    return tokens.size() == 3 || tokens[3] == "vpn_gateway" || tokens[3] == "default";
}

// Applies one redirect-gateway / redirect-private / route option to the running IPv4 state, the way
// OpenVPN's add_option() does.
void applyRoutingOption(const QStringList &tokens, bool &redirectIpv4, bool &lowerHalf, bool &upperHalf)
{
    const QString name = directiveName(tokens);
    if (name == "redirect-gateway" || name == "redirect-private") {
        if (tokens.contains("!ipv4")) {
            redirectIpv4 = false;
        } else if (name == "redirect-gateway") {
            redirectIpv4 = true;
        }
    } else if (name == "route") {
        if (isTunnelRoute(tokens, "0.0.0.0", "0.0.0.0")) {
            lowerHalf = upperHalf = true;
        } else if (isTunnelRoute(tokens, "0.0.0.0", "128.0.0.0")) {
            lowerHalf = true;
        } else if (isTunnelRoute(tokens, "128.0.0.0", "128.0.0.0")) {
            upperHalf = true;
        }
    }
}

bool isRouteOption(const QString &name)
{
    return name == "redirect-gateway" || name == "redirect-private" || name == "route";
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
    bool lowerHalf = hasLowerHalfRoute;
    bool upperHalf = hasUpperHalfRoute;
    for (const QString &rawOption : pushedOptions) {
        const QString option = rawOption.trimmed();
        const QStringList tokens = tokenizeOvpnLine(option);
        if (!isRouteOption(directiveName(tokens)) || !isPushedOptionAccepted(option)) {
            continue;
        }
        applyRoutingOption(tokens, redirectIpv4, lowerHalf, upperHalf);
    }
    return redirectIpv4 || (lowerHalf && upperHalf);
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
        if (name.isEmpty()) {
            continue;
        }
        // Only directives that reach the daemon count. The helper strips the ones not on its allowlist,
        // among them route-noexec and redirect-private (the patched daemon would reject them anyway).
        if (name == "redirect-gateway" || name == "route") {
            applyRoutingOption(tokens, policy.redirectsIpv4Locally, policy.hasLowerHalfRoute, policy.hasUpperHalfRoute);
        } else if (name == "route-nopull") {
            policy.routeNopull = true;
        } else if (name == "pull-filter" && tokens.size() >= 3) {
            policy.pullFilters.append(OvpnPullFilter{tokens[1], tokens[2]});
        }
    }

#ifdef Q_OS_WIN
    // For a config whose remote is the local wrapper (stunnel/wstunnel), the Windows helper adds
    // "--route 0.0.0.0 128.0.0.0 vpn_gateway --route 128.0.0.0 128.0.0.0 vpn_gateway" on the command
    // line (helper/windows/openvpn/openvpncontroller.cpp), using the same text test.
    if (config.contains("remote 127.0.0.1")) {
        policy.hasLowerHalfRoute = policy.hasUpperHalfRoute = true;
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
