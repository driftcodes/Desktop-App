#pragma once

#include <mutex>
#include <thread>
#include <set>
#include <string>
#include <vector>

#include "apps_ids.h"
#include "fwpm_wrapper.h"
#include "scoped_permit_plan.h"
#include "../common/helper_commands.h"
#include "types/ipaddress.h"

class DnsFirewall
{
public:
    static DnsFirewall &instance(FwpmWrapper *wrapper = nullptr)
    {
        static DnsFirewall df(*wrapper);
        return df;
    }
    ~DnsFirewall();

    void release();

    // false when the rules could not be removed; they then stay whole. Requests are carried out for
    // the filter's current owner only (DnsLeakFilterOwnership); others are ignored and return true /
    // kApplied.
    // keepRules: the owner only lets go (hand-over); the rules stay in place, unwatched, until the
    // next owner's enable replaces them in one transaction or a later disable removes them.
    bool disable(DnsLeakFilterOwner requester, bool keepRules = false);
    // Blocks port 53 to every adapter's DNS servers (minus the custom connected DNS). permitApps (a
    // proxied session that is not connected) blocks every local-network range as well, so a router
    // on a network joined meanwhile is covered too, applies no exclusions, and lets Windscribe's own
    // programs and Exclusive-mode excluded apps through: Windscribe resolves its API and imported
    // hostnames itself while reconnecting, and excluded apps such as Throne bypass the VPN by the
    // user's choice. Calling it again rebuilds the rules in one transaction, so the block never lapses;
    // a failed rebuild keeps the rules in place. While enabled, a monitor rebuilds the rules when the
    // adapters' DNS servers change (also on the same network) and retries a rebuild that failed.
    // excludeIps: the custom connected DNS addresses not blocked while connected; taken only if the
    // request is the owner's.
    DnsLeakFilterResult enable(bool permitApps, DnsLeakFilterOwner requester, const std::set<types::IpAddress> &excludeIps);

    void setWindscribeAppsIds(const AppsIds &appsIds);
    void setExcludedAppsIds(const AppsIds &appsIds);

private:
    std::recursive_mutex mutex_;
    scoped_permits::DnsFilterRequests requests_;  // owner, and what it wants
    bool bCurrentState_;           // rules of this filter are in place
    bool isDirty_ = false;         // the last rebuild failed or was incomplete
    AppsIds windscribeAppsIds_;
    AppsIds excludedAppsIds_;
    scoped_permits::PermittedAppsTracker<AppsIds> permittedApps_;
    std::set<types::IpAddress> appliedServers_;  // the adapters' DNS servers the rules in place cover
    GUID subLayerGUID_;
    FwpmWrapper &fwmpWrapper_;

    std::thread monitor_;
    HANDLE stopMonitorEvent_ = nullptr;

    explicit DnsFirewall(FwpmWrapper &fwmpWrapper);
    // Rebuilds the rules for what requests_ holds.
    DnsLeakFilterResult enableImpl();
    void updatePermittedApps();
    // false when the adapters could not be read (an empty set is a valid answer).
    bool getDnsServers(std::set<types::IpAddress> &dnsServers);

    void startMonitor();
    void stopMonitor();
    void monitorThread();
    void checkForChanges();
};
