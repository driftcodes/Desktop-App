#pragma once

#include <QSharedPointer>
#include "types/proxysettings.h"

class UniqueIpList;

class FirewallExceptions
{
public:
    FirewallExceptions();

    void setHostIPs(const QSet<QString> &hostIPs);
    void setProxyIP(const types::ProxySettings &proxySettings);

    void setCustomRemoteIp(const QString &remoteIP, bool &bChanged);
    void setConnectingIp(const QString &connectingIp, bool &bChanged);
    void setDNSServers(const QStringList &ips, bool &bChanged);

    void setDnsPolicy(DNS_POLICY_TYPE dnsPolicy);

    void setLocationsPingIps(const QStringList &listIps);
    void setCustomConfigPingIps(const QStringList &listIps);

    QSet<QString> getIPAddressesForFirewall() const;
    QSet<QString> getIPAddressesForFirewallForConnectedState() const;

    // Whether a proxy (HTTP or SOCKS) carries the app's traffic and its OpenVPN TCP connections.
    bool isProxySet() const { return !proxyIP_.isEmpty(); }

    // The exceptions to use while not connected (disconnected, connecting, reconnecting):
    // - Firewall Always On+: only what the connected state allows (as before);
    // - a proxy is set: the API and the OpenVPN TCP connection go through it, so the API hosts and the
    //   ping targets are left out (they are permitted for every program, and a reconnect would reopen
    //   them while the tunnel is down). Kept: loopback, the proxy, the advanced-parameters remote and
    //   the DNS servers (incl. ControlD): wsnet resolves every API hostname itself before handing the
    //   request to curl, even through a proxy, imported hostnames are looked up before dialing, and
    //   ctrld starts before the tunnel is up;
    // - otherwise: the full list (getIPAddressesForFirewall).
    QSet<QString> getIPAddressesForNotConnectedState(bool isAlwaysOnPlus) const;

    // Forgets the finished connection's own exceptions: the server it dialed and its DNS servers.
    void clearConnectionExceptions();

    const QString& connectingIp() const;

private:
    void addDnsServers(UniqueIpList &ipList) const;

    QSet<QString> hostIPs_;
    QString proxyIP_;
    QString remoteIP_;
    QStringList locationsPingIPs_;
    QStringList customConfigsPingIPs_;
    QString connectingIp_;
    QStringList dnsIps_;
    DNS_POLICY_TYPE dnsPolicyType_;

};
