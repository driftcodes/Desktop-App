#include <WinSock2.h>
#include <ws2ipdef.h>

#include "ip_routes.h"
#include "../../adapters_info.h"

#include <cstring>
#include <set>
#include <spdlog/spdlog.h>

namespace {

// Fill a SOCKADDR_INET from types::IpAddress. Family is taken from ip.
void fillSockaddrInet(SOCKADDR_INET *out, const types::IpAddress &ip)
{
    std::memset(out, 0, sizeof(SOCKADDR_INET));
    if (ip.isV4()) {
        out->Ipv4.sin_family = AF_INET;
        std::memcpy(&out->Ipv4.sin_addr, ip.bytes(), 4);
    } else if (ip.isV6()) {
        out->Ipv6.sin6_family = AF_INET6;
        std::memcpy(&out->Ipv6.sin6_addr, ip.bytes(), 16);
    }
}

// Returns interface metric for the given family/ifIndex; 0 on error.
ULONG getInterfaceMetric(unsigned long ifIndex, ADDRESS_FAMILY family)
{
    MIB_IPINTERFACE_ROW interfaceRow;
    std::memset(&interfaceRow, 0, sizeof(interfaceRow));
    interfaceRow.Family = family;
    interfaceRow.InterfaceIndex = ifIndex;
    DWORD dwErr = GetIpInterfaceEntry(&interfaceRow);
    if (dwErr != NO_ERROR) {
        spdlog::error("IpRoutes: GetIpInterfaceEntry(family={}) failed with error: {}",
                      static_cast<int>(family), dwErr);
        return 0;
    }
    return interfaceRow.Metric;
}

// True when the row is directly attached (unspecified next hop).
bool isOnLink(const MIB_IPFORWARD_ROW2 &row)
{
    static const IN6_ADDR kZeroV6 = {};
    if (row.NextHop.si_family == AF_INET)
        return row.NextHop.Ipv4.sin_addr.S_un.S_addr == 0;
    if (row.NextHop.si_family == AF_INET6)
        return std::memcmp(&row.NextHop.Ipv6.sin6_addr, &kZeroV6, sizeof(kZeroV6)) == 0;
    return false;
}

bool isInterfaceConnected(unsigned long ifIndex, ADDRESS_FAMILY family)
{
    MIB_IPINTERFACE_ROW interfaceRow;
    std::memset(&interfaceRow, 0, sizeof(interfaceRow));
    interfaceRow.Family = family;
    interfaceRow.InterfaceIndex = ifIndex;
    DWORD dwErr = GetIpInterfaceEntry(&interfaceRow);
    if (dwErr != NO_ERROR) {
        // ERROR_NOT_FOUND is expected if the interface disappears mid-scan; don't warn for it
        // since this is called once per on-link route row.
        if (dwErr == ERROR_NOT_FOUND) {
            spdlog::debug("IpRoutes: GetIpInterfaceEntry(ifIndex={}, family={}) not found", ifIndex, static_cast<int>(family));
        } else {
            spdlog::warn("IpRoutes: GetIpInterfaceEntry(ifIndex={}, family={}) failed with error: {}",
                         ifIndex, static_cast<int>(family), dwErr);
        }
    }
    return dwErr == NO_ERROR && interfaceRow.Connected;
}

types::IpAddressRange toRange(const IP_ADDRESS_PREFIX &prefix)
{
    if (prefix.Prefix.si_family == AF_INET) {
        return types::IpAddressRange(
            types::IpAddress(types::IpAddress::IPv4,
                             reinterpret_cast<const uint8_t *>(&prefix.Prefix.Ipv4.sin_addr), 4),
            static_cast<uint8_t>(prefix.PrefixLength));
    }
    if (prefix.Prefix.si_family == AF_INET6) {
        return types::IpAddressRange(
            types::IpAddress(types::IpAddress::IPv6,
                             reinterpret_cast<const uint8_t *>(&prefix.Prefix.Ipv6.sin6_addr), 16),
            static_cast<uint8_t>(prefix.PrefixLength));
    }
    return types::IpAddressRange();
}

// Destinations the OS can already reach without a gateway over a live interface.
// Windows resolves equal-prefix routes by effective metric (RouteMetric + InterfaceMetric), and the
// exclusion rows below carry the physical interface metric in both terms, so they can outrank a
// directly attached subnet's on-link row (metric 256 + interface metric) and hijack its traffic.
// Each route keeps whether its adapter may carry an exclusion (not the Windscribe tunnel), and each
// family whether its table could be read at all.
struct OnLinkScan {
    std::vector<route_set::OnLinkRoute<types::IpAddressRange>> routes;
    bool isReadV4 = false;
    bool isReadV6 = false;
};

OnLinkScan collectOnLinkRoutes(unsigned long intendedIfIndex)
{
    OnLinkScan result;
    AdaptersInfo adapters;
    static const ADDRESS_FAMILY kFamilies[] = { AF_INET, AF_INET6 };
    for (const ADDRESS_FAMILY family : kFamilies) {
        PMIB_IPFORWARD_TABLE2 table = nullptr;
        DWORD dwErr = GetIpForwardTable2(family, &table);
        if (dwErr != NO_ERROR || table == nullptr) {
            spdlog::warn("IpRoutes: GetIpForwardTable2(family={}) failed with error: {}", static_cast<int>(family), dwErr);
            continue;
        }
        (family == AF_INET ? result.isReadV4 : result.isReadV6) = true;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2 &row = table->Table[i];
            if (!isOnLink(row) || !isInterfaceConnected(row.InterfaceIndex, family))
                continue;
            const auto dest = toRange(row.DestinationPrefix);
            if (!dest.isValid())
                continue;
            // The intended adapter, or one known not to be the tunnel (unknown if the adapters could
            // not be listed: then only the intended one counts).
            const bool isUsable = row.InterfaceIndex == intendedIfIndex ||
                                  (adapters.isListed() && !adapters.isAppVpnAdapter(row.InterfaceIndex));
            result.routes.push_back({dest, isUsable});
        }
        FreeMibTable(table);
    }
    return result;
}

bool isLoopbackDestination(const types::IpAddressRange &ip)
{
    const types::IpAddress &address = ip.address();
    if (address.isV4()) {
        return address.bytes()[0] == 127;
    }
    if (address.isV6()) {
        static const uint8_t kLoopbackV6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return std::memcmp(address.bytes(), kLoopbackV6, 16) == 0;
    }
    return false;
}

} // namespace

IpRoutes::IpRoutes()
{
}

bool IpRoutes::setIps(const types::IpAddress &gatewayIp,
                      const types::IpAddress &gatewayIpV6,
                      unsigned long ifIndex,
                      const std::vector<types::IpAddressRange> &ips,
                      bool isExclude)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    // Fetched lazily: only exclude mode can collide with an existing on-link route, and only
    // when there is at least one new destination to install.
    bool haveOnLinkRoutes = false;
    OnLinkScan onLink;
    // Exclude mode: whether the destination is reached directly (see route_set::directPath).
    const auto directPath = [&](const types::IpAddressRange &ip) {
        if (!isExclude) {
            return isLoopbackDestination(ip) ? route_set::DirectPath::kDirect : route_set::DirectPath::kNotDirect;
        }
        if (!haveOnLinkRoutes) {
            onLink = collectOnLinkRoutes(ifIndex);
            haveOnLinkRoutes = true;
        }
        return route_set::directPath(ip, isLoopbackDestination(ip), ip.isV6() ? onLink.isReadV6 : onLink.isReadV4,
                                     onLink.routes);
    };

    // Cache per-family metric — fetched lazily on first need.
    bool haveMetricV4 = false, haveMetricV6 = false;
    ULONG metricV4 = 0, metricV6 = 0;

    // Deduplicate input.
    std::set<types::IpAddressRange> ipsSet;
    for (const auto &ip : ips) {
        if (ip.isValid())
            ipsSet.insert(ip);
    }

    const auto needsNoRoute = [&](const types::IpAddressRange &ip) {
        if (directPath(ip) == route_set::DirectPath::kDirect) {
            // Already reached without a gateway (the local subnet, loopback): the intended path.
            spdlog::info("IpRoutes::setIps(), {} is directly attached, keeping the existing on-link route", ip.toString());
            return true;
        }
        const bool hasGatewayV4 = gatewayIp.isValid() && gatewayIp.isV4();
        const bool hasGatewayV6 = gatewayIpV6.isValid() && gatewayIpV6.isV6();
        if (route_set::needsNoRouteForFamily(ip.isV6(), hasGatewayV4, hasGatewayV6)) {
            spdlog::warn("IpRoutes::setIps(), no IPv6 on this network for v6 destination {}", ip.toString());
            return true;
        }
        return false;
    };

    const auto create = [&](const types::IpAddressRange &ip, MIB_IPFORWARD_ROW2 &row) {
        const types::IpAddress *gw = nullptr;
        ULONG metric = 0;
        if (directPath(ip) == route_set::DirectPath::kUnknown) {
            // The routing table could not be read: it may be a directly attached subnet, which a
            // gateway route would hijack. Not in place; retried with the next update.
            spdlog::error("IpRoutes::setIps(), the routing table could not be read; not routing {}", ip.toString());
            return route_set::CreateResult::kFailed;
        }
        if ((ip.isV4() && !(gatewayIp.isValid() && gatewayIp.isV4())) ||
            (ip.isV6() && !(gatewayIpV6.isValid() && gatewayIpV6.isV6())) || (!ip.isV4() && !ip.isV6())) {
            // No gateway to route it through: not in place (retried with the next update).
            spdlog::error("IpRoutes::setIps(), no gateway of its family for {}", ip.toString());
            return route_set::CreateResult::kFailed;
        }
        if (ip.isV4()) {
            gw = &gatewayIp;
            if (!haveMetricV4) {
                metricV4 = getInterfaceMetric(ifIndex, AF_INET);
                haveMetricV4 = true;
            }
            metric = metricV4;
        } else {
            gw = &gatewayIpV6;
            if (!haveMetricV6) {
                metricV6 = getInterfaceMetric(ifIndex, AF_INET6);
                haveMetricV6 = true;
            }
            metric = metricV6;
        }

        InitializeIpForwardEntry(&row);
        row.InterfaceIndex = ifIndex;
        row.DestinationPrefix.PrefixLength = ip.prefixLength();
        fillSockaddrInet(&row.DestinationPrefix.Prefix, ip.address());
        fillSockaddrInet(&row.NextHop, *gw);
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Metric = metric;

        const DWORD status = CreateIpForwardEntry2(&row);
        if (status == NO_ERROR) {
            return route_set::CreateResult::kCreated;
        }
        if (status == ERROR_OBJECT_ALREADY_EXISTS) {
            // A route for this prefix on this interface exists; it is the intended path only through
            // the same next hop. Read back by prefix, interface and next hop: found means exactly ours.
            MIB_IPFORWARD_ROW2 existing = row;
            const DWORD lookup = GetIpForwardEntry2(&existing);
            if (lookup == NO_ERROR && existing.InterfaceIndex == row.InterfaceIndex &&
                existing.DestinationPrefix.PrefixLength == row.DestinationPrefix.PrefixLength &&
                std::memcmp(&existing.NextHop, &row.NextHop, sizeof(row.NextHop)) == 0) {
                spdlog::info("IpRoutes::setIps(), the route for {} already exists", ip.toString());
                return route_set::CreateResult::kAlreadyThere;
            }
            // Through another next hop: someone else's, left alone; not in place.
            spdlog::error("IpRoutes::setIps(), a route for {} through another next hop exists (lookup {}); not ours to replace",
                          ip.toString(), lookup);
            return route_set::CreateResult::kFailed;
        }
        spdlog::error("IpRoutes::setIps(), CreateIpForwardEntry2 failed for {}: {}", ip.toString(), status);
        return route_set::CreateResult::kFailed;
    };

    const bool isApplied = routes_.apply(ipsSet, needsNoRoute, create, &IpRoutes::removeRoute);
    if (!isApplied) {
        spdlog::error("IpRoutes::setIps(), not every route is in place ({} left to delete)", routes_.staleCount());
    }
    return isApplied;
}

bool IpRoutes::areApplied(const std::vector<types::IpAddressRange> &ips)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    std::set<types::IpAddressRange> ipsSet;
    for (const auto &ip : ips) {
        if (ip.isValid())
            ipsSet.insert(ip);
    }
    return routes_.isApplied(ipsSet);
}

route_set::DeleteResult IpRoutes::removeRoute(const MIB_IPFORWARD_ROW2 &row)
{
    MIB_IPFORWARD_ROW2 copy = row;
    const DWORD status = DeleteIpForwardEntry2(&copy);
    if (status == NO_ERROR) {
        return route_set::DeleteResult::kDeleted;
    }
    if (status == ERROR_NOT_FOUND) {
        spdlog::info("IpRoutes: DeleteIpForwardEntry2 did not find the route");
        return route_set::DeleteResult::kNotFound;
    }
    // Kept and deleted again on the next update or clear.
    spdlog::error("IpRoutes: DeleteIpForwardEntry2 failed: {}", status);
    return route_set::DeleteResult::kFailed;
}

bool IpRoutes::hasLeftovers()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return routes_.hasLeftovers();
}

bool IpRoutes::clear()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return routes_.clear(&IpRoutes::removeRoute);
}
