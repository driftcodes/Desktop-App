#include "makeovpnfile.h"

#include <QRegularExpression>
#include <QString>

#include "utils/extraconfig.h"
#include "utils/log/categories.h"
#include "utils/networkingvalidation.h"
#include "utils/ws_assert.h"
#include "api_responses/amneziawgunblockparams.h"
#include <wsnet/WSNet.h>

MakeOVPNFile::MakeOVPNFile()
{
}

MakeOVPNFile::~MakeOVPNFile()
{
}

void MakeOVPNFile::appendDnsOverride(QString &config, const QString &dnsServer)
{
    config += "\r\npull-filter ignore \"dhcp-option DNS\"\r\n";
    config += QString("dhcp-option DNS %1\r\n").arg(dnsServer);
}

namespace {

// Directive tokens of one config line, quotes removed. Empty for blank and comment lines.
QStringList directiveTokens(const QString &line)
{
    const QString trimmed = line.trimmed();
    if (trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith(';')) {
        return QStringList();
    }
    QStringList tokens = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    for (QString &token : tokens) {
        token.remove('"');
        token.remove('\'');
    }
    // Directives may be written with a leading "--", as on the command line.
    if (!tokens.isEmpty() && tokens.first().startsWith("--")) {
        tokens.first().remove(0, 2);
    }
    return tokens;
}

} // namespace

bool MakeOVPNFile::applyLoopbackProxyRouteFix(QString &config)
{
    const QStringList lines = config.split('\n');

    QStringList kept;
    kept.reserve(lines.size());
    bool insideInlineBlock = false;
    int removedRedirectGateway = 0;
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        // Inline blocks (<ca>...</ca> and the like) hold key material, never directives.
        if (insideInlineBlock) {
            if (trimmed.startsWith("</")) {
                insideInlineBlock = false;
            }
            kept << line;
            continue;
        }
        if (trimmed.startsWith('<') && !trimmed.startsWith("</")) {
            insideInlineBlock = true;
            kept << line;
            continue;
        }

        const QStringList tokens = directiveTokens(line);
        if (!tokens.isEmpty()) {
            const QString &directive = tokens.first();
            if (directive.compare("route-nopull", Qt::CaseInsensitive) == 0 ||
                directive.compare("route-noexec", Qt::CaseInsensitive) == 0 ||
                (directive.compare("pull-filter", Qt::CaseInsensitive) == 0 && tokens.size() >= 3 &&
                 tokens[1].compare("ignore", Qt::CaseInsensitive) == 0 &&
                 tokens[2].compare("redirect-gateway", Qt::CaseInsensitive) == 0)) {
                qCInfo(LOG_CONNECTION) << "Loopback proxy route fix not applied: the config already opts out of redirect-gateway";
                return false;
            }
            if (directive.compare("redirect-gateway", Qt::CaseInsensitive) == 0) {
                removedRedirectGateway++;
                continue;
            }
        }
        kept << line;
    }

    // pull-filter rules are matched first to last, so ours must precede any the config carries.
    config = "pull-filter ignore redirect-gateway\r\n" + kept.join('\n');
    config += "\r\nroute 0.0.0.0 128.0.0.0 vpn_gateway\r\n";
    config += "route 128.0.0.0 128.0.0.0 vpn_gateway\r\n";

    qCInfo(LOG_CONNECTION) << "Loopback proxy route fix applied: redirect-gateway replaced by 0.0.0.0/1 and 128.0.0.0/1 tunnel routes"
                           << "(removed" << removedRedirectGateway << "redirect-gateway line(s) from the config)";
    return true;
}

bool MakeOVPNFile::generate(const QString &ovpnData, const QString &ip, types::Protocol protocol, uint port,
                            uint portForStunnelOrWStunnel, int mss, const QString &defaultGateway,
                            const QString &openVpnX509, const QString &customDns, bool isAntiCensorship,
                            const QString &awgPreset)
{
#ifdef Q_OS_WIN
    Q_UNUSED(defaultGateway);
#endif

    if (!NetworkingValidation::isIp(ip)) {
        qCCritical(LOG_CONNECTION) << "MakeOVPNFile::generate: refusing to build config, node IP is not a valid IP address";
        return false;
    }

    QString strExtraConfig = ExtraConfig::instance().getExtraConfigForOpenVpn();
    bool bExtraContainsRemote = !ExtraConfig::instance().getRemoteIpFromExtraConfig().isEmpty();

    config_ = ovpnData;

    // Set timeout to 30s according to this: https://www.notion.so/windscribe/Data-Plane-VPN-Protocol-Failover-Refresh-48ed7aea1a244617b327c3a7d816a902
    config_ += "\r\nconnect-timeout 30\r\n";

    if (protocol == types::Protocol::OPENVPN_UDP) {
        if (!bExtraContainsRemote) {
            config_ += "\r\nremote " + ip;
        }
        config_ += "\r\nport " + QString::number(port);
        config_ += "\r\nproto udp\r\n";

        if (mss > 0) {
            config_ += QString("mssfix %1\r\n").arg(mss);
        }
    } else if (protocol == types::Protocol::OPENVPN_TCP) {
        if (!bExtraContainsRemote) {
            config_ += "\r\nremote " + ip;
        }
        config_ += "\r\nport " + QString::number(port);
        config_ += "\r\nproto tcp-client\r\n";
    } else if (protocol.isStunnelOrWStunnelProtocol()) {
        if (!bExtraContainsRemote) {
            config_ += "\r\nremote 127.0.0.1";
        }
        config_ += QString("\r\nport %1").arg(portForStunnelOrWStunnel);
        config_ += "\r\nproto tcp-client\r\n";
#if defined (Q_OS_MACOS) || defined (Q_OS_LINUX)
        if (!defaultGateway.isEmpty()) {
            qCInfo(LOG_CONNECTION) << "defaultGateway for stunnel/wstunnel ovpn config: " << defaultGateway;
            config_ += QString("route %1 255.255.255.255 %2\r\n").arg(ip).arg(defaultGateway);
        }
#endif
    } else {
        WS_ASSERT(false);
    }

    if (openVpnX509 != "") {
        // openVpnX509 is a server-provided value written verbatim into a config line; a CR/LF or
        // other control character would inject an OpenVPN directive. Reject control characters and
        // Unicode line/paragraph separators, but allow non-ASCII: a legitimate X.509 name may carry
        // UTF-8 characters.
        for (const QChar &c : openVpnX509) {
            const QChar::Category cat = c.category();
            if (cat == QChar::Other_Control || cat == QChar::Separator_Line || cat == QChar::Separator_Paragraph) {
                qCCritical(LOG_CONNECTION) << "MakeOVPNFile::generate: refusing to build config, verify-x509-name contains a control character";
                return false;
            }
        }
        config_ += QString("verify-x509-name %1 name\r\n").arg(openVpnX509);
    }

    if (!customDns.isEmpty()) {
        appendDnsOverride(config_, customDns);
    }

    // concatenate with advanced parameters file, if it exists
    if (!strExtraConfig.isEmpty()) {
        qCInfo(LOG_CONNECTION) << "Adding extra options to OVPN config:" << strExtraConfig;
        config_ += strExtraConfig;
    }

    if (isAntiCensorship) {
        config_ += "udp-stuffing\n";
        config_ += "tcp-split-reset\n";

        // Add I1-I5 parameters if available
        // NOTE: Emergency connect supplies empty string here
        if (!awgPreset.isEmpty()) {
            api_responses::AmneziawgUnblockParams unblockParams(
                wsnet::WSNet::instance()->apiResourcersManager()->amneziawgUnblockParams());

            if (unblockParams.isValid()) {
                api_responses::AmneziawgUnblockParam param =
                    unblockParams.getUnblockParamForPreset(awgPreset);

                // Add I1-I5 parameters (in order, only if they exist)
                for (int i = 0; i < param.iValues.size() && i < 5; ++i) {
                    if (!param.iValues[i].isEmpty()) {
                        // Sanitize iValue: allow only alphanumeric, space, digits, and angle brackets
                        // Strip newlines and other special characters
                        QString sanitizedValue;
                        for (const QChar &ch : param.iValues[i]) {
                            if (ch.isLetterOrNumber() || ch.isSpace() || ch == '<' || ch == '>') {
                                sanitizedValue += ch;
                            }
                        }
                        config_ += QString("i%1 \"%2\"\n").arg(i + 1).arg(sanitizedValue);
                    }
                }

                if (!param.iValues.isEmpty()) {
                    qCInfo(LOG_CONNECTION) << "Added" << param.iValues.size()
                                        << "I-parameters to OpenVPN config from preset:"
                                        << awgPreset;
                }
            }
        }
    }

    return true;
}
