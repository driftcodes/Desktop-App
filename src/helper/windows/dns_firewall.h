#pragma once

#include <functional>
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

    // The DNS baseline (see scoped_permits::dnsBaselineRules): on with the main firewall, off with
    // it. Its block and program permits are persistent, like the firewall's rules, so they are in
    // place once Windows loads persistent filters at boot with Always On. While on, the monitor
    // rebuilds it when Windscribe's tunnel adapters, the programs or the custom DNS change, and
    // retries a rebuild that failed. Returns whether its blocks are in place (always true for off).
    bool setBaselineEnabled(bool isEnabled);
    // Called (from the monitor, outside its lock) when a baseline that was not in place gets in.
    void setBaselineReadyCallback(std::function<void()> callback);
    // Service start with the firewall kept from before (firewall on boot): keep the persistent rules
    // left in place (they cover every adapter and already permit the excluded apps, which the client
    // only sends later) and rebuild once the client has sent them, or a tunnel adapter appears. One
    // is built if none is there.
    // Returns whether a baseline is in place afterwards; if not, the caller holds the main firewall's
    // LAN permit.
    bool adoptBaselineAtStart();
    bool isBaselineInPlace();
    // Service start without a baseline, the firewall's LAN permit could not be removed: the monitor
    // retries hold() until it succeeds, the baseline gets in, or the client's firewallOn/Off clears it.
    void setPendingLanHold(std::function<bool()> hold);
    void clearPendingLanHold();
    // Run on every monitor tick (about every 2 s while the firewall is on), outside its lock: retries
    // of other firewall updates that failed (split-tunnel permits).
    void setPeriodicTask(std::function<void()> task);

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

    // The baseline.
    GUID baselineSubLayerGUID_;
    GUID legacyBaselineSubLayerGUID_;
    bool isBaselineEnabled_ = false;
    bool isBaselineInPlace_ = false;           // its blocks are installed
    bool isReadyNotificationPending_ = false;  // got in since the monitor last looked
    std::function<void()> baselineReadyCallback_;
    std::function<bool()> pendingLanHold_;
    std::function<void()> periodicTask_;
    bool isBaselineDirty_ = false;
    bool isWaitingForExcludedApps_ = false;   // adopted at start: keep it until the client's list comes
    bool isExcludedAppsKnown_ = false;
    std::set<uint64_t> baselineTunnels_;              // the tunnel adapters it permits
    std::set<types::IpAddress> baselineAddresses_;    // the addresses it permits (connected custom DNS)
    scoped_permits::PermittedAppsTracker<AppsIds> baselineApps_;

    std::thread monitor_;
    HANDLE stopMonitorEvent_ = nullptr;

    explicit DnsFirewall(FwpmWrapper &fwmpWrapper);
    // Rebuilds the rules for what requests_ holds.
    DnsLeakFilterResult enableImpl();
    void updatePermittedApps();
    // false when the adapters could not be read (an empty set is a valid answer).
    bool getDnsServers(std::set<types::IpAddress> &dnsServers);
    // Also Windscribe's own (tunnel) adapters, by LUID; their DNS servers are not included.
    bool getAdapters(std::set<types::IpAddress> &dnsServers, std::set<uint64_t> &tunnelInterfaces);

    // The custom connected DNS addresses the baseline permits: only while the session filter is in
    // its connected mode.
    std::set<types::IpAddress> baselinePermittedAddresses() const;
    void applyBaselineImpl();
    void updateBaselineIfNeeded();
    bool removeBaselineImpl();
    bool removeSublayerWithFilters(const GUID &subLayer);
    // Looks for the baseline's global port-53 blocks among the installed filters.
    void findBaselineBlocks(bool &isV4Found, bool &isV6Found);
    void addTunnelPermitsWhileWaiting();
    // Removes the baseline's non-persistent filters (tunnel / custom DNS permits) left from before the
    // service restarted; the persistent block and program permits stay.
    bool removeSessionOnlyBaselineFilters();

    void startMonitor();
    void stopMonitor();
    void monitorThread();
    void checkForChanges();
};
