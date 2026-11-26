#pragma once

#include <mutex>
#include <vector>

#include "apps_ids.h"
#include "fwpm_wrapper.h"
#include "types/ipaddress.h"
#include "scoped_permit_plan.h"

class Ipv6Firewall
{
public:
    enum class SplitTunnelMode { Disabled, Inclusive, Exclusive };

    static Ipv6Firewall &instance(FwpmWrapper *wrapper = nullptr)
    {
        static Ipv6Firewall ip6f(*wrapper);
        return ip6f;
    }

    void release();

    // Lift / install the IPv6 block. false if not committed: the rules in place stay as they were, and
    // the request is retried by retryPending() (periodic) until a newer one replaces it.
    bool enableIPv6();
    bool disableIPv6(bool allowLanTraffic, bool isCustomConfig);
    void retryPending();

    // Split tunneling carve-outs in the global v6 block.
    // Inclusive: apps = tunnel-bound apps (included apps + VPN executables); everything else
    // gets native v6. Exclusive: apps = excluded apps; they get native v6.
    void setSplitTunnelingState(SplitTunnelMode mode, const AppsIds &apps);

    // Split tunneling IP/hostname list (manual entries + resolved hostnames, dual-stack;
    // v4 entries are ignored). Inclusive: off-tunnel v6 to these destinations is blocked so
    // it falls back to v4, which the routes carry into the tunnel. Exclusive: native v6 to
    // these destinations is permitted. Updates incrementally when the filters are installed.
    void setSplitTunnelingWhitelistIps(const std::vector<types::IpAddressRange> &ips);

private:
    explicit Ipv6Firewall(FwpmWrapper &fwpmWrapper);

    FwpmWrapper &fwpmWrapper_;
    GUID subLayerGUID_;
    std::recursive_mutex mutex_;
    bool isDisabled_ = false;
    bool allowLanTraffic_ = false;
    bool isCustomConfig_ = false;
    SplitTunnelMode splitTunnelMode_ = SplitTunnelMode::Disabled;
    AppsIds splitTunnelAppsIds_;
    std::vector<types::IpAddressRange> whitelistIps_;
    std::vector<UINT64> whitelistFilterIds_;
    scoped_permits::Ipv6FirewallRequests requests_;
    // false if a required block could not be added.
    bool addFilters(HANDLE engineHandle, bool allowLanTraffic, bool isCustomConfig);
    bool applyWhitelistFiltersLocked(HANDLE engineHandle);
    // false if a filter could not be deleted (and was not already gone).
    bool removeWhitelistFiltersLocked(HANDLE engineHandle);
    // Commits the open transaction if isComplete (and reports whether it committed); aborts otherwise.
    bool commitOrAbort(bool isComplete);
};
