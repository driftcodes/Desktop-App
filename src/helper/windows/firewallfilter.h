#pragma once

#include "ws_branding.h"
#include "apps_ids.h"
#include "fwpm_wrapper.h"
#include "types/ipaddress.h"

#define UUID_LAYER L"367016b3-3af8-4966-8442-d8bb6435f4a0"
#define FIREWALL_SUBLAYER_NAMEW WS_APP_IDENTIFIER_W L"Firewall"

class FirewallFilter
{
public:
    static FirewallFilter &instance(FwpmWrapper *wrapper = nullptr)
    {
        static FirewallFilter ff(*wrapper);
        return ff;
    }

    void release();

    // ips are permitted for every program; windscribeOnlyIps only for Windscribe's own programs (see
    // setWindscribeAppsIds) - not svchost, so the Windows DNS client cannot relay other programs'
    // lookups through them.
    void on(const wchar_t *connectingIp, const std::vector<std::wstring> &ips, const std::vector<std::wstring> &windscribeOnlyIps,
            bool bAllowLocalTraffic, bool bIsCustomConfig);
    void off();
    bool currentStatus();

    // split tunnelling parameters
    void setSplitTunnelingEnabled(bool isExclusiveMode);
    void setSplitTunnelingDisabled();

    void setSplitTunnelingAppsIds(const AppsIds &appsIds);
    // Dual-stack: ips holds IPv4 and/or IPv6 ranges; family is dispatched in
    // addPermitFilterForSplitRoutingWhitelistIps via isV4()/isV6().
    void setSplitTunnelingWhitelistIps(const std::vector<types::IpAddressRange> &ips);
    void setVpnAppsIds(const AppsIds &appsIds);
    // Windscribe's own programs for windscribeOnlyIps: the client and its bundled tools, ctrld and the
    // helper service.
    void setWindscribeAppsIds(const AppsIds &appsIds);

private:
    FwpmWrapper &fwpmWrapper_;
    GUID   subLayerGUID_;

    std::recursive_mutex mutex_;
    bool lastAllowLocalTraffic_;

    explicit FirewallFilter(FwpmWrapper &fwmpWrapper);

    bool currentStatusImpl(HANDLE engineHandle);
    void offImpl(HANDLE engineHandle);

    void addFilters(HANDLE engineHandle, const wchar_t *connectingIp, const std::vector<std::wstring> &ips,
                    const std::vector<std::wstring> &windscribeOnlyIps, bool bAllowLocalTraffic, bool bIsCustomConfig);
    void addPermitFilterForVpnAndSystemServices(HANDLE engineHandle, const wchar_t *ip);
    void addPermitFilterForAppsIds(HANDLE engineHandle);
    void addPermitFilterForSplitRoutingWhitelistIps(HANDLE engineHandle);

    void removeAppsSplitTunnelingFilter(HANDLE engineHandle);
    void removeIpsSplitTunnelingFilter(HANDLE engineHandle);
    void removeAllSplitTunnelingFilters(HANDLE engineHandle);

    std::vector<std::wstring> tapAdapters_;

    bool isSplitTunnelingEnabled_;
    bool isSplitTunnelingExclusiveMode_;
    AppsIds appsIds_;
    AppsIds vpnAppsIds_;
    AppsIds windscribeAppsIds_;
    std::vector<types::IpAddressRange> splitRoutingIps_;

    std::vector<UINT64> filterIdsApps_;
    std::vector<UINT64> filterIdsSplitRoutingIps_;
};
