#pragma once

#include "hostnames_manager/hostnames_manager.h"
#include "callout_filter.h"
#include "routes_manager.h"
#include "split_tunnel_service_manager.h"
#include "../apps_ids.h"

class SplitTunneling
{
public:
    static SplitTunneling &instance(FwpmWrapper *wrapper = nullptr)
    {
        static SplitTunneling st(*wrapper);
        return st;
    }

    void release();

    void setSettings(bool isEnabled, bool isExclude, const std::vector<std::wstring>& apps, const std::vector<std::wstring>& ips,
                     const std::vector<std::string>& hosts, bool isAllowLanTraffic);
    bool setConnectStatus(ConnectStatus& connectStatus);
    bool updateState();

    // What this helper applies, for the client to compare with what it asked for: a helper that
    // restarted runs on its defaults (split tunneling off, no apps) until the client sends them again.
    struct Confirmation {
        bool isEnabled;
        bool isExclude;
        std::vector<std::wstring> apps;
        bool areAppsResolved;
    };
    Confirmation confirmation() const { return {isSplitTunnelEnabled_, isExclude_, apps_, unresolvedApps_.empty()}; }

    static void removeAllFilters(FwpmWrapper& fwmpWrapper);

    // Looks for Windscribe's programs again when none could be identified at service start (the
    // scoped firewall and DNS permits need them). Returns how many are known afterwards.
    size_t redetectWindscribeAppsIfMissing();

private:
    CalloutFilter calloutFilter_;
    RoutesManager routesManager_;
    HostnamesManager hostnamesManager_;
    SplitTunnelServiceManager splitTunnelServiceManager_;

    AppsIds vpnMainExecutableId_;
    AppsIds vpnOtherExecutablesId_;
    AppsIds ctrldExecutableId_;

    ConnectStatus connectStatus_;
    bool isSplitTunnelEnabled_ = false;
    bool isExclude_ = false;
    bool isAllowLanTraffic_ = false;
    std::vector<std::wstring> apps_;
    std::vector<std::wstring> unresolvedApps_;
    bool prevIsSplitTunnelActive_ = false;
    bool prevIsExclude_ = false;
    // LUID of the VPN adapter of the last connected state. Kept after disconnect: a "default
    // adapter" with this LUID is the tunnel, never a valid exclusive redirect target (#2048).
    // While a later session is not connected yet, the per-app and per-destination blocks stay on
    // this adapter so a reconnect does not lift them while it is still up.
    // Not the ifIndex: Windows reuses the index of a removed tunnel adapter for a new physical
    // one, which would then be mistaken for the tunnel.
    UINT64 lastVpnLuid_ = 0;
    size_t windscribeAppsCount_ = 0;

    SplitTunneling(FwpmWrapper& fwpmWrapper);
    void detectVpnExecutables();
    void publishWindscribeAppsIds();
};
