#pragma once

#include <functional>

#include "ws_branding.h"
#include "apps_ids.h"
#include "fwpm_wrapper.h"
#include "types/ipaddress.h"
#include "scoped_permit_plan.h"

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
    // lookups through them. Returns false when a requested permit could not be added (e.g. Windscribe's
    // programs are unknown, so windscribeOnlyIps get no permit); the firewall is on either way.
    // bHoldLanPermit: turn the firewall on without its LAN permit (Allow LAN / custom config), e.g.
    // while the DNS baseline that keeps DNS off the LAN is not in place yet.
    bool on(const wchar_t *connectingIp, const std::vector<std::wstring> &ips, const std::vector<std::wstring> &windscribeOnlyIps,
            bool bAllowLocalTraffic, bool bIsCustomConfig, bool bHoldLanPermit = false);
    // false if the firewall could not be removed completely: nothing changed then (aborted), it stays
    // whole.
    bool off();
    // Removes the LAN permits of the firewall in place (kept from before, at service start) and
    // blocks DNS to IPv6 link-local: while no DNS baseline is in place they would let any program
    // query a router's DNS.
    bool holdLanPermit();
    // Retries bringing the split-tunnel filters (app and IP exclusions) in line with the latest
    // settings, after an update that failed or could not read the firewall's state; called periodically.
    void retryPendingSplitTunnelUpdate();
    // true only if the firewall is known to be on (see firewallStatus()).
    bool currentStatus();
    // On, off, or unknown (the state could not be read).
    scoped_permits::FirewallStatus firewallStatus();

    // split tunnelling parameters: each changes its part of the latest request, then the filters are
    // rebuilt from the whole request (see scoped_permits::SplitTunnelFilterSync)
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
    scoped_permits::FirewallStatus firewallStatusImpl(HANDLE engineHandle);
    bool offImpl(HANDLE engineHandle);

    bool addFilters(HANDLE engineHandle, const wchar_t *connectingIp, const std::vector<std::wstring> &ips,
                    const std::vector<std::wstring> &windscribeOnlyIps, bool bAllowLocalTraffic, bool bIsCustomConfig,
                    bool bHoldLanPermit, bool areDefaultBlocksAdded[2], bool *isSplitTunnelComplete);
    void addPermitFilterForVpnAndSystemServices(HANDLE engineHandle, const wchar_t *ip);
    bool addLinkLocalDnsBlock(HANDLE engineHandle);
    // Runs body in one WFP transaction; if it does not commit, the recorded split-tunnel filter ids
    // are put back as they were (Windows keeps the old filters). Returns whether it committed.
    // body returns false when a step failed (e.g. a filter could not be deleted): aborted then.
    bool runTransaction(const std::function<bool()> &body);
    // The split-tunnel filters (from the latest request) and their sync; with mutex_ held.
    bool addSplitTunnelingFilters(HANDLE engineHandle);
    void syncSplitTunnelFilters();
    bool addPermitFilterForAppsIds(HANDLE engineHandle);
    bool addPermitFilterForSplitRoutingWhitelistIps(HANDLE engineHandle);

    // false if a filter could not be deleted (and was not already gone).
    bool removeAppsSplitTunnelingFilter(HANDLE engineHandle);
    bool removeIpsSplitTunnelingFilter(HANDLE engineHandle);
    bool removeAllSplitTunnelingFilters(HANDLE engineHandle);

    std::vector<std::wstring> tapAdapters_;

    // The split-tunnel settings requested (mode, excluded apps and IPs) and what Windows confirmed.
    scoped_permits::SplitTunnelFilterSync<scoped_permits::SplitTunnelState<AppsIds, std::vector<types::IpAddressRange>>> splitTunnel_;
    AppsIds vpnAppsIds_;
    AppsIds windscribeAppsIds_;

    std::vector<UINT64> filterIdsApps_;
    std::vector<UINT64> filterIdsSplitRoutingIps_;
};
