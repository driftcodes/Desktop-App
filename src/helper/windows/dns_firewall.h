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

    void disable();
    // Blocks port 53 to every adapter's DNS servers. permitApps (a proxied session that is not
    // connected) also lets Windscribe's own programs and Exclusive-mode excluded apps reach them:
    // Windscribe resolves its API and imported hostnames itself while reconnecting, and excluded
    // apps such as Throne bypass the VPN by the user's choice. Calling it again rebuilds the rules in
    // one transaction, so the block never lapses.
    void enable(bool permitApps = false);

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
    void enableImpl();
    void addFilters(HANDLE engineHandle, const std::set<types::IpAddress> &dnsServers, AppsIds &permittedApps);
    std::set<types::IpAddress> getDnsServers();
};
