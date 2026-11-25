#include "ws_branding.h"
#include <spdlog/spdlog.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Fwpmu.h>
#include <iphlpapi.h>

#include "dns_firewall.h"
#include "scoped_permit_plan.h"
#include "utils.h"
#include "utils/log/debug_trace.h"

#define FIREWALL_SUBLAYER_DNS_NAMEW WS_APP_IDENTIFIER_W L"DnsFirewallSublayer"
#define UUID_LAYER_DNS L"7e4a5678-bc70-45e8-8674-21a8e610fd02"


DnsFirewall::DnsFirewall(FwpmWrapper &fwmpWrapper) : fwmpWrapper_(fwmpWrapper), bCurrentState_(false)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    UuidFromString((RPC_WSTR)UUID_LAYER_DNS, &subLayerGUID_);
}

void DnsFirewall::release()
{
    disable();
    WSACleanup();
}

void DnsFirewall::disable()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();

    fwmpWrapper_.beginTransaction();
    bCurrentState_ = false;
    bPermitApps_ = false;

    if (Utils::deleteSublayerAndAllFilters(hEngine, &subLayerGUID_)) {
        spdlog::debug("DnsFirewall::disable(), all filters deleted");
    } else {
        spdlog::debug("DnsFirewall::disable(), deleteSublayerAndAllFilters returned false (sublayer may not exist)");
    }

    fwmpWrapper_.endTransaction();
    fwmpWrapper_.unlock();
}

void DnsFirewall::enable(bool permitApps)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    bPermitApps_ = permitApps;
    enableImpl();
}

void DnsFirewall::enableImpl()
{
    AppsIds permittedApps;
    if (bPermitApps_) {
        permittedApps.addFrom(windscribeAppsIds_);
        permittedApps.addFrom(excludedAppsIds_);
        if (permittedApps.count() == 0) {
            spdlog::error("DnsFirewall::enable(), no permitted programs known; blocking DNS for every program");
        }
    }
    const auto dnsServers = getDnsServers();

    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    fwmpWrapper_.beginTransaction();

    // Old rules out and new rules in within one transaction: re-enabling (e.g. switching between the
    // connected and the reconnecting rules) never leaves a moment without the block.
    Utils::deleteSublayerAndAllFilters(hEngine, &subLayerGUID_);

    FWPM_SUBLAYER0 subLayer = { 0 };

    subLayer.subLayerKey = subLayerGUID_;
    subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
    subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
    subLayer.flags = 0;
    subLayer.weight = 0xFFFF;

    DWORD dwFwAPiRetCode = FwpmSubLayerAdd0(hEngine, &subLayer, NULL);
    if (dwFwAPiRetCode != ERROR_SUCCESS && dwFwAPiRetCode != FWP_E_ALREADY_EXISTS) {
        spdlog::error("DnsFirewall::enable(), FwpmSubLayerAdd0 failed: {}", dwFwAPiRetCode);
        // Keep whatever rules were there before.
        fwmpWrapper_.abortTransaction();
        fwmpWrapper_.unlock();
        return;
    }

    addFilters(hEngine, dnsServers, permittedApps);

    fwmpWrapper_.endTransaction();
    fwmpWrapper_.unlock();
    bCurrentState_ = true;
}

void DnsFirewall::setExcludeIps(const std::vector<std::wstring>& ips)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    excludeIps_.clear();
    for (const auto &w : ips) {
        types::IpAddress addr(w);
        if (addr.isValid()) {
            excludeIps_.insert(addr);
        }
    }
}

void DnsFirewall::setWindscribeAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (windscribeAppsIds_ == appsIds) {
        return;
    }
    windscribeAppsIds_ = appsIds;
    if (bCurrentState_ && bPermitApps_) {
        enableImpl();
    }
}

void DnsFirewall::setExcludedAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (excludedAppsIds_ == appsIds) {
        return;
    }
    excludedAppsIds_ = appsIds;
    if (bCurrentState_ && bPermitApps_) {
        enableImpl();
    }
}

void DnsFirewall::addFilters(HANDLE engineHandle, const std::set<types::IpAddress> &dnsServers, AppsIds &permittedApps)
{
    // For each DNS server: a block of port 53 (UDP and TCP) for every program, weight 6, above the
    // main firewall's LAN permit (4), so a router in a private range is covered too; and, when
    // programs are permitted, a permit for just them at weight 7, which wins within this sublayer.
    // The main firewall still decides separately whether those programs may reach the address.
    for (const auto &rule : scoped_permits::dnsFilterRules(dnsServers, excludeIps_, permittedApps.count())) {
        const auto &ip = rule.server;
        // Wrap the single host as a dual-stack range; addFilterV4/V6 dispatch by family
        // (the wrong-family call is a no-op).
        const uint8_t prefix = ip.isV4() ? 32 : 128;
        const std::vector<types::IpAddressRange> addr = { types::IpAddressRange(ip, prefix) };
        const FWP_ACTION_TYPE action = rule.isPermitForApps ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
        const UINT8 weight = rule.isPermitForApps ? 7 : 6;
        AppsIds *apps = rule.isPermitForApps ? &permittedApps : nullptr;
        bool ret = false;
        if (ip.isV4()) {
            ret = Utils::addFilterV4(engineHandle, nullptr, action, weight, subLayerGUID_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        } else if (ip.isV6()) {
            ret = Utils::addFilterV6(engineHandle, nullptr, action, weight, subLayerGUID_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        }

        const char *kind = rule.isPermitForApps ? "permit (permitted programs)" : "block";
        if (!ret) {
            spdlog::error("Could not add DNS {} filter for {}", kind, ip.toString());
        } else {
            spdlog::debug("Added DNS {} filter for {}", kind, ip.toString());
        }
    }
    for (const auto &ip : dnsServers) {
        if (excludeIps_.count(ip) > 0) {
            spdlog::debug("DnsFirewall::addFilters(), ip excluded: {}", ip.toString());
        }
    }
}

std::set<types::IpAddress> DnsFirewall::getDnsServers()
{
    WS_DEBUG_TRACE_SCOPE("DnsFirewall::getDnsServers");
    std::set<types::IpAddress> dnsServers;

    DWORD dwRetVal = 0;
    ULONG outBufLen = 0;
    ULONG iterations = 0;
    const int MAX_TRIES = 5;
    std::vector<unsigned char> arr;
    arr.resize(1);

    outBufLen = static_cast<ULONG>(arr.size());
    do {
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, NULL, NULL, (PIP_ADAPTER_ADDRESSES)&arr[0], &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            arr.resize(outBufLen);
        } else {
            break;
        }
        iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

    if (dwRetVal != NO_ERROR) {
        spdlog::error("DnsFirewall::getDnsServers(), GetAdaptersAddresses failed: {}", dwRetVal);
        return {};
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = (PIP_ADAPTER_ADDRESSES)&arr[0];
    while (pCurrAddresses) {
        // Warning: we control the FriendlyName of the wireguard-nt adapter, but not the Description.
        if ((wcsstr(pCurrAddresses->Description, WS_PRODUCT_NAME_W) == 0) &&
            (wcsstr(pCurrAddresses->FriendlyName, WS_PRODUCT_NAME_W) == 0)) {
            PIP_ADAPTER_DNS_SERVER_ADDRESS dnsServerAddress = pCurrAddresses->FirstDnsServerAddress;
            while (dnsServerAddress) {
                const auto family = dnsServerAddress->Address.lpSockaddr->sa_family;
                if (family == AF_INET) {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(dnsServerAddress->Address.lpSockaddr);
                    types::IpAddress addr(types::IpAddress::IPv4,
                                          reinterpret_cast<const uint8_t *>(&sin->sin_addr), 4);
                    if (addr.isValid()) {
                        dnsServers.insert(std::move(addr));
                    }
                } else if (family == AF_INET6) {
                    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(dnsServerAddress->Address.lpSockaddr);
                    types::IpAddress addr(types::IpAddress::IPv6,
                                          reinterpret_cast<const uint8_t *>(&sin6->sin6_addr), 16);
                    if (addr.isValid()) {
                        dnsServers.insert(std::move(addr));
                    }
                }
                dnsServerAddress = dnsServerAddress->Next;
            }
        }

        pCurrAddresses = pCurrAddresses->Next;
    }

    return dnsServers;
}
