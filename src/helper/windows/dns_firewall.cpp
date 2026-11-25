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

DnsFirewall::~DnsFirewall()
{
    stopMonitor();
}

void DnsFirewall::release()
{
    disable();
    stopMonitor();
    WSACleanup();
}

namespace {

// The DnsFirewall sublayer's rules in one WFP transaction (see scoped_permits::replaceDnsRules).
class WfpDnsRuleStore : public scoped_permits::DnsRuleStore
{
public:
    WfpDnsRuleStore(FwpmWrapper &wrapper, HANDLE engine, const GUID &subLayer, AppsIds &permittedApps)
        : wrapper_(wrapper), engine_(engine), subLayer_(subLayer), permittedApps_(permittedApps) {}

    bool begin() override { return wrapper_.beginTransaction(); }

    bool removeAll() override
    {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(engine_, &subLayer_, layer, &allDeleted);
        }
        return allDeleted;
    }

    bool ensureSublayer() override
    {
        FWPM_SUBLAYER0 subLayer = { 0 };
        subLayer.subLayerKey = subLayer_;
        subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
        subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
        subLayer.flags = 0;
        subLayer.weight = 0xFFFF;
        const DWORD ret = FwpmSubLayerAdd0(engine_, &subLayer, NULL);
        if (ret != ERROR_SUCCESS && ret != FWP_E_ALREADY_EXISTS) {
            spdlog::error("DnsFirewall: FwpmSubLayerAdd0 failed: {}", ret);
            return false;
        }
        return true;
    }

    bool add(const scoped_permits::DnsRule &rule) override
    {
        // Blocks at weight 6, above the main firewall's LAN permit (4); permits for the permitted
        // programs at 7, which win within this sublayer. The main firewall still decides separately
        // whether those programs may reach the address.
        const std::vector<types::IpAddressRange> addr = { rule.target };
        const FWP_ACTION_TYPE action = rule.isPermitForApps ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
        const UINT8 weight = rule.isPermitForApps ? 7 : 6;
        AppsIds *apps = rule.isPermitForApps ? &permittedApps_ : nullptr;
        bool ret = false;
        if (rule.target.isV4()) {
            ret = Utils::addFilterV4(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        } else if (rule.target.isV6()) {
            ret = Utils::addFilterV6(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        }
        const char *kind = rule.isPermitForApps ? "permit (permitted programs)" : "block";
        if (!ret) {
            spdlog::error("Could not add DNS {} filter for {}", kind, rule.target.toString());
        } else {
            spdlog::debug("Added DNS {} filter for {}", kind, rule.target.toString());
        }
        return ret;
    }

    bool commit() override { return wrapper_.endTransaction(); }
    void abort() override { wrapper_.abortTransaction(); }

private:
    FwpmWrapper &wrapper_;
    HANDLE engine_;
    GUID subLayer_;
    AppsIds &permittedApps_;
};

} // namespace

bool DnsFirewall::disable()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    bWanted_ = false;
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();

    bool isRemoved = false;
    if (fwmpWrapper_.beginTransaction()) {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(hEngine, &subLayerGUID_, layer, &allDeleted);
        }
        if (allDeleted) {
            const DWORD ret = FwpmSubLayerDeleteByKey0(hEngine, &subLayerGUID_);
            if (ret != ERROR_SUCCESS && ret != FWP_E_SUBLAYER_NOT_FOUND) {
                spdlog::error("DnsFirewall::disable(), FwpmSubLayerDeleteByKey0 failed: {}", ret);
            }
            isRemoved = fwmpWrapper_.endTransaction();
        } else {
            // Keep it whole rather than half removed; the client retries.
            fwmpWrapper_.abortTransaction();
        }
    }
    fwmpWrapper_.unlock();

    if (isRemoved) {
        bCurrentState_ = false;
        isDirty_ = false;
        appliedServers_.clear();
        permittedApps_.onNoPermitsInPlace();
        spdlog::debug("DnsFirewall::disable(), all filters deleted");
    } else {
        spdlog::error("DnsFirewall::disable() failed; the DNS leak filter stays as it was");
    }
    return isRemoved;
}

DnsLeakFilterResult DnsFirewall::enable(bool permitApps)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    startMonitor();
    return enableImpl(permitApps);
}

DnsLeakFilterResult DnsFirewall::enableImpl(bool permitApps)
{
    bWanted_ = true;
    bWantedPermitApps_ = permitApps;

    AppsIds permittedApps;
    if (permitApps) {
        permittedApps = permittedApps_.requested();
        if (permittedApps.count() == 0) {
            spdlog::error("DnsFirewall::enable(), no permitted programs known; blocking DNS for every program");
        }
    }
    std::set<types::IpAddress> dnsServers;
    const bool serversKnown = getDnsServers(dnsServers);
    const auto plan = scoped_permits::planDnsRules(serversKnown, dnsServers, appliedServers_, excludeIps_, permitApps,
                                                   permittedApps.count());

    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    WfpDnsRuleStore store(fwmpWrapper_, hEngine, subLayerGUID_, permittedApps);
    // Old rules out and new rules in within one transaction, aborted (keeping the old rules) unless
    // every block is in: re-enabling never leaves a moment without the block.
    const auto result = scoped_permits::replaceDnsRules(store, plan.canApply, plan.rules);
    fwmpWrapper_.unlock();

    if (result == scoped_permits::ReplaceResult::kKeptPrevious) {
        spdlog::error("DnsFirewall::enable() failed (adapters readable: {}); the previous rules stay", serversKnown);
        isDirty_ = true;
        return DnsLeakFilterResult::kFailed;
    }
    bCurrentState_ = true;
    if (!plan.isFallback) {
        appliedServers_ = dnsServers;
    }
    if (permitApps && result == scoped_permits::ReplaceResult::kApplied) {
        permittedApps_.onApplied();
    } else {
        permittedApps_.onNoPermitsInPlace();
    }
    isDirty_ = plan.isFallback || result != scoped_permits::ReplaceResult::kApplied;
    if (isDirty_) {
        spdlog::error("DnsFirewall::enable(), blocks in place but incomplete (adapters unreadable: {}); will retry",
                      plan.isFallback);
        return DnsLeakFilterResult::kIncomplete;
    }
    return DnsLeakFilterResult::kApplied;
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
    windscribeAppsIds_ = appsIds;
    updatePermittedApps();
}

void DnsFirewall::setExcludedAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    excludedAppsIds_ = appsIds;
    updatePermittedApps();
}

void DnsFirewall::updatePermittedApps()
{
    AppsIds permitted = windscribeAppsIds_;
    permitted.addFrom(excludedAppsIds_);
    // Compared with the programs of the rules in place, not with the last request: after a failed
    // rebuild the old permits are still there, so the same list sent again must still rebuild.
    if (permittedApps_.request(permitted) && bWanted_ && bWantedPermitApps_) {
        enableImpl(true);  // on failure isDirty_ is set and the monitor retries
    }
}

void DnsFirewall::startMonitor()
{
    if (monitor_.joinable()) {
        return;
    }
    stopMonitorEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (stopMonitorEvent_ == NULL) {
        spdlog::error("DnsFirewall: CreateEvent failed: {}", ::GetLastError());
        return;
    }
    monitor_ = std::thread(&DnsFirewall::monitorThread, this);
}

void DnsFirewall::stopMonitor()
{
    if (!monitor_.joinable()) {
        return;
    }
    SetEvent(stopMonitorEvent_);
    monitor_.join();
    CloseHandle(stopMonitorEvent_);
    stopMonitorEvent_ = nullptr;
}

void DnsFirewall::monitorThread()
{
    // Windows keeps each adapter's DNS servers (static and DHCP) under these keys; a change there is
    // the earliest sign of a new resolver, on the same network or another. A short poll backs it up
    // and retries a rebuild that failed.
    const wchar_t *paths[2] = {L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                               L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces"};
    HKEY keys[2] = {nullptr, nullptr};
    HANDLE events[3] = {stopMonitorEvent_, CreateEvent(NULL, FALSE, FALSE, NULL), CreateEvent(NULL, FALSE, FALSE, NULL)};
    const auto arm = [&](int i) {
        if (keys[i] != nullptr && events[i + 1] != NULL) {
            const LONG ret = RegNotifyChangeKeyValue(keys[i], TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                                     events[i + 1], TRUE);
            if (ret != ERROR_SUCCESS) {
                spdlog::error("DnsFirewall: RegNotifyChangeKeyValue failed: {}", ret);
            }
        }
    };
    for (int i = 0; i < 2; ++i) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_NOTIFY, &keys[i]) != ERROR_SUCCESS) {
            keys[i] = nullptr;
            spdlog::error(L"DnsFirewall: could not watch {}; polling only", paths[i]);
        }
        arm(i);
    }
    const DWORD count = (events[1] != NULL && events[2] != NULL) ? 3 : 1;

    constexpr DWORD kPollMs = 2000;
    while (true) {
        const DWORD wait = WaitForMultipleObjects(count, events, FALSE, kPollMs);
        if (wait == WAIT_OBJECT_0) {
            break;
        }
        if (wait == WAIT_OBJECT_0 + 1) {
            arm(0);
        } else if (wait == WAIT_OBJECT_0 + 2) {
            arm(1);
        } else if (wait == WAIT_FAILED) {
            spdlog::error("DnsFirewall: WaitForMultipleObjects failed: {}", ::GetLastError());
            if (WaitForSingleObject(stopMonitorEvent_, kPollMs) == WAIT_OBJECT_0) {
                break;
            }
        }
        checkForChanges();
    }

    for (int i = 0; i < 2; ++i) {
        if (keys[i] != nullptr) {
            RegCloseKey(keys[i]);
        }
        if (events[i + 1] != NULL) {
            CloseHandle(events[i + 1]);
        }
    }
}

void DnsFirewall::checkForChanges()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!bWanted_) {
        return;
    }
    std::set<types::IpAddress> servers;
    const bool serversKnown = getDnsServers(servers);
    const bool serversChanged = scoped_permits::dnsServersChanged(serversKnown, servers, appliedServers_);
    const bool appsChanged = bWantedPermitApps_ && permittedApps_.needsRebuild();
    if (isDirty_ || serversChanged || appsChanged) {
        spdlog::info("DnsFirewall: rebuilding (retry: {}, DNS servers changed: {}, programs changed: {})", isDirty_,
                     serversChanged, appsChanged);
        enableImpl(bWantedPermitApps_);
    }
}

bool DnsFirewall::getDnsServers(std::set<types::IpAddress> &dnsServers)
{
    WS_DEBUG_TRACE_SCOPE("DnsFirewall::getDnsServers");
    dnsServers.clear();

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
        // An error, unlike a network without DNS servers (ERROR_NO_DATA: no adapters at all).
        if (dwRetVal == ERROR_NO_DATA) {
            return true;
        }
        spdlog::error("DnsFirewall::getDnsServers(), GetAdaptersAddresses failed: {}", dwRetVal);
        return false;
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

    return true;
}
