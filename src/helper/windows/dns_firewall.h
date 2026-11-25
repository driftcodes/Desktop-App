#pragma once

#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "apps_ids.h"
#include "fwpm_wrapper.h"
#include "types/ipaddress.h"

class DnsFirewall
{
public:
    static DnsFirewall &instance(FwpmWrapper *wrapper = nullptr)
    {
        static DnsFirewall df(*wrapper);
        return df;
    }

    void release();

    // Both return false when the rules could not be (fully) applied; the previous rules then stay
    // (enable keeps them unless every new block is in).
    bool disable();
    // Blocks port 53 to every adapter's DNS servers (minus the custom connected DNS). permitApps (a
    // proxied session that is not connected) blocks every local-network range as well, so a router
    // on a network joined meanwhile is covered too, applies no exclusions, and lets Windscribe's own
    // programs and Exclusive-mode excluded apps through: Windscribe resolves its API and imported
    // hostnames itself while reconnecting, and excluded apps such as Throne bypass the VPN by the
    // user's choice. Calling it again rebuilds the rules in one transaction, so the block never lapses.
    bool enable(bool permitApps = false);

    void setExcludeIps(const std::vector<std::wstring>& ips);
    void setWindscribeAppsIds(const AppsIds &appsIds);
    void setExcludedAppsIds(const AppsIds &appsIds);

private:
    std::recursive_mutex mutex_;
    bool bCurrentState_;
    bool bPermitApps_ = false;
    AppsIds windscribeAppsIds_;
    AppsIds excludedAppsIds_;
    GUID subLayerGUID_;
    FwpmWrapper &fwmpWrapper_;
    std::set<types::IpAddress> excludeIps_;

    explicit DnsFirewall(FwpmWrapper &fwmpWrapper);
    bool enableImpl(bool permitApps);
    // false when the adapters could not be read (an empty set is a valid answer).
    bool getDnsServers(std::set<types::IpAddress> &dnsServers);
};
