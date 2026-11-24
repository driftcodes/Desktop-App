#include "ovpnroutingpolicy.h"

#include <QRegularExpression>
#include <QStringList>

namespace customconfigs {

namespace {

// Directive tokens of one config line, quotes removed and a leading "--" dropped. Empty for blank
// and comment lines.
QStringList directiveTokens(const QString &line)
{
    const QString trimmed = line.trimmed();
    if (trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith(';')) {
        return QStringList();
    }
    static const QRegularExpression whitespace("\\s+");
    QStringList tokens = trimmed.split(whitespace, Qt::SkipEmptyParts);
    for (QString &token : tokens) {
        token.remove('"');
        token.remove('\'');
    }
    if (!tokens.isEmpty() && tokens.first().startsWith("--")) {
        tokens.first().remove(0, 2);
    }
    return tokens;
}

// A "route" line that sends traffic into the tunnel: no gateway given, or vpn_gateway.
bool isTunnelRoute(const QStringList &tokens, const QString &network, const QString &netmask)
{
    if (tokens.size() < 3 || tokens[1] != network || tokens[2] != netmask) {
        return false;
    }
    return tokens.size() == 3 || tokens[3].compare("vpn_gateway", Qt::CaseInsensitive) == 0 ||
           tokens[3].compare("default", Qt::CaseInsensitive) == 0;
}

} // namespace

OvpnRoutingPolicy analyzeOvpnRouting(const QString &config)
{
    OvpnRoutingPolicy policy;
    bool hasLowerHalfRoute = false;
    bool hasUpperHalfRoute = false;
    bool pushFilterDecided = false;
    bool insideInlineBlock = false;

    // The pushed option OpenVPN would match pull-filter rules against.
    const QString pushedRedirect = "redirect-gateway def1";

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

        const QStringList tokens = directiveTokens(line);
        if (tokens.isEmpty()) {
            continue;
        }
        const QString directive = tokens.first().toLower();

        if (directive == "redirect-gateway") {
            bool ipv4 = true;
            for (int i = 1; i < tokens.size(); ++i) {
                if (tokens[i] == "!ipv4") {
                    ipv4 = false;
                }
            }
            if (ipv4) {
                policy.redirectsIpv4Locally = true;
            }
        } else if (directive == "route") {
            if (isTunnelRoute(tokens, "0.0.0.0", "0.0.0.0")) {
                hasLowerHalfRoute = hasUpperHalfRoute = true;
            } else if (isTunnelRoute(tokens, "0.0.0.0", "128.0.0.0")) {
                hasLowerHalfRoute = true;
            } else if (isTunnelRoute(tokens, "128.0.0.0", "128.0.0.0")) {
                hasUpperHalfRoute = true;
            }
        } else if (directive == "route-nopull") {
            policy.ignoresPushedRedirect = true;
        } else if (directive == "route-noexec") {
            policy.routesNotExecuted = true;
        } else if (directive == "pull-filter" && tokens.size() >= 3 && !pushFilterDecided) {
            // OpenVPN applies the first rule whose text is a prefix of the pushed option.
            const QString &text = tokens[2];
            if (pushedRedirect.startsWith(text, Qt::CaseSensitive) || text.startsWith("redirect-gateway")) {
                pushFilterDecided = true;
                const QString action = tokens[1].toLower();
                if (action == "ignore" || action == "reject") {
                    policy.ignoresPushedRedirect = true;
                }
            }
        }
    }

    if (hasLowerHalfRoute && hasUpperHalfRoute) {
        policy.redirectsIpv4Locally = true;
    }
    return policy;
}

} // namespace customconfigs
