#include "ws_branding.h"
#include <windows.h>
#include <Fwpmu.h>

#include <spdlog/spdlog.h>

#include "ipv6_firewall.h"
#include "utils.h"
#include "adapters_info.h"
#include "scoped_permit_plan.h"

#define FIREWALL_SUBLAYER_IPV6_NAMEW WS_APP_IDENTIFIER_W L"IPV6FirewallSublayer"
#define UUID_LAYER_IPV6 L"8b03e426-56a7-4669-a985-706406675e68"

Ipv6Firewall::Ipv6Firewall(FwpmWrapper &fwpmWrapper): fwpmWrapper_(fwpmWrapper)
{
    UuidFromString((RPC_WSTR)UUID_LAYER_IPV6, &subLayerGUID_);
}

void Ipv6Firewall::release()
{
    enableIPv6();
}

bool Ipv6Firewall::commitOrAbort(bool isComplete)
{
    if (isComplete && fwpmWrapper_.endTransaction()) {
        return true;
    }
    // WFP would otherwise commit the operations that did succeed (e.g. some deletions only).
    fwpmWrapper_.abortTransaction();
    return false;
}

bool Ipv6Firewall::enableIPv6()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    sync_.requestUnblock();
    return sync_.step() == scoped_permits::Ipv6BlockSync::Step::kNothing || unblockImpl();
}

bool Ipv6Firewall::disableIPv6(bool allowLanTraffic, bool isCustomConfig)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    // Remember for rebuilds triggered by setSplitTunnelingState() and for retries.
    allowLanTraffic_ = allowLanTraffic;
    isCustomConfig_ = isCustomConfig;
    sync_.requestBlock();
    return blockImpl();
}

bool Ipv6Firewall::isSublayerPresent(HANDLE engineHandle, bool &isPresent)
{
    FWPM_SUBLAYER0 *subLayer = nullptr;
    const DWORD ret = FwpmSubLayerGetByKey0(engineHandle, &subLayerGUID_, &subLayer);
    if (ret == ERROR_SUCCESS) {
        FwpmFreeMemory0((void **)&subLayer);
        isPresent = true;
        return true;
    }
    if (ret == FWP_E_SUBLAYER_NOT_FOUND) {
        isPresent = false;
        return true;
    }
    spdlog::error("Ipv6Firewall: FwpmSubLayerGetByKey0 failed: {}", ret);
    return false;
}

bool Ipv6Firewall::unblockImpl()
{
    // Always against what Windows has, not what this process remembers: a previous process (or
    // service run) may have left the persistent block in place.
    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    bool isDone = fwpmWrapper_.beginTransaction();
    if (isDone) {
        const bool isRemoved = Utils::deleteSublayerAndAllFilters(hEngine, &subLayerGUID_);
        if (!isRemoved) {
            spdlog::error("Ipv6Firewall: the IPv6 block's filters could not all be deleted; aborted, they stay");
        }
        isDone = commitOrAbort(isRemoved);
    }
    if (isDone) {
        bool isPresent = true;
        isDone = isSublayerPresent(hEngine, isPresent) && !isPresent;
        if (!isDone) {
            spdlog::error("Ipv6Firewall: the IPv6 block is not confirmed gone");
        }
    }
    fwpmWrapper_.unlock();

    // Recorded only once committed and confirmed; otherwise retried.
    if (isDone) {
        whitelistFilterIds_.clear();
        sync_.onUnblockCommitted();
    } else {
        sync_.onFailed();
    }
    return isDone;
}

bool Ipv6Firewall::blockImpl()
{
    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    if (!fwpmWrapper_.beginTransaction()) {
        spdlog::error("Ipv6Firewall: could not begin a transaction; the IPv6 rules in place stay, retrying");
        fwpmWrapper_.unlock();
        sync_.onFailed();
        return false;
    }
    const std::vector<UINT64> prevFilterIds = whitelistFilterIds_;

    // Rebuild the filters from scratch on every call, not just on the disabled->enabled edge:
    // a reconnect may land on a different tunnel adapter, and the Allow LAN setting may have
    // changed while connected. Bailing out when already disabled would keep stale tunnel
    // permits / stale LAN rules. One transaction: committed only with the old filters all gone and
    // the new blocks in; otherwise the rules in place stay as they were.
    bool isComplete = Utils::deleteSublayerAndAllFilters(hEngine, &subLayerGUID_);
    if (!isComplete) {
        spdlog::error("Ipv6Firewall: the existing filters could not all be deleted");
    }
    whitelistFilterIds_.clear();

    if (isComplete) {
        FWPM_SUBLAYER0 subLayer = { 0 };

        subLayer.subLayerKey = subLayerGUID_;
        subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_IPV6_NAMEW;
        subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_IPV6_NAMEW;
        subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        subLayer.weight = 0xFFFF;

        DWORD dwFwAPiRetCode = FwpmSubLayerAdd0(hEngine, &subLayer, NULL);
        if (dwFwAPiRetCode != ERROR_SUCCESS && dwFwAPiRetCode != FWP_E_ALREADY_EXISTS) {
            spdlog::error("Ipv6Firewall: FwpmSubLayerAdd0 failed: {}", dwFwAPiRetCode);
            isComplete = false;
        }
    }
    bool arePermitsComplete = true;
    if (isComplete && !addFilters(hEngine, allowLanTraffic_, isCustomConfig_, arePermitsComplete)) {
        spdlog::error("Ipv6Firewall: a required block could not be added");
        isComplete = false;
    }

    const bool isDone = commitOrAbort(isComplete);
    fwpmWrapper_.unlock();
    if (isDone) {
        if (!arePermitsComplete) {
            // The blocks are in (fail closed); the missing permit (e.g. an excluded app's IPv6) is retried.
            spdlog::error("Ipv6Firewall: IPv6 blocked, but a permit is missing; retrying");
        }
        sync_.onBlockCommitted(arePermitsComplete);
    } else {
        spdlog::error("Ipv6Firewall: block aborted; the IPv6 rules in place stay, retrying");
        whitelistFilterIds_ = prevFilterIds;
        sync_.onFailed();
    }
    return isDone;
}

void Ipv6Firewall::retryPending()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    switch (sync_.step()) {
    case scoped_permits::Ipv6BlockSync::Step::kBlock:
        spdlog::info("Ipv6Firewall: retrying the IPv6 block");
        blockImpl();
        break;
    case scoped_permits::Ipv6BlockSync::Step::kUnblock:
        spdlog::info("Ipv6Firewall: retrying lifting the IPv6 block");
        unblockImpl();
        break;
    default:
        break;
    }
}

void Ipv6Firewall::setSplitTunnelingState(SplitTunnelMode mode, const AppsIds &apps)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    if (mode == splitTunnelMode_ && apps == splitTunnelAppsIds_) {
        return;
    }

    spdlog::debug("Ipv6Firewall::setSplitTunnelingState, mode={}, apps={}", (int)mode, apps.count());
    splitTunnelMode_ = mode;
    splitTunnelAppsIds_ = apps;

    // While the block is wanted, rebuild it with the new state; a pending lift stays a lift.
    sync_.onSettingsChanged();
    if (sync_.step() == scoped_permits::Ipv6BlockSync::Step::kBlock) {
        blockImpl();
    }
}

void Ipv6Firewall::setSplitTunnelingWhitelistIps(const std::vector<types::IpAddressRange> &ips)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    if (ips == whitelistIps_) {
        return;
    }
    // The latest list asked for; the rules are built from it.
    whitelistIps_ = ips;

    if (!sync_.canUpdateInPlace()) {
        // Not installed (or a rebuild is pending anyway): the next block / rebuild picks it up.
        sync_.onSettingsChanged();
        return;
    }

    // Incremental update: replace only the destination filters, keeping the rest of the
    // sublayer intact (this is called on every hostname resolution). Committed only with the old
    // ones all deleted and the new ones added: committing with only the removals applied would drop
    // the inclusive off-tunnel BLOCK and leak forced destinations' v6.
    const std::vector<UINT64> prevFilterIds = whitelistFilterIds_;

    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    bool isDone = fwpmWrapper_.beginTransaction();
    if (isDone) {
        const bool isRemoved = removeWhitelistFiltersLocked(hEngine);
        isDone = commitOrAbort(isRemoved && applyWhitelistFiltersLocked(hEngine));
    }
    fwpmWrapper_.unlock();
    if (!isDone) {
        // The old filters stay; a full rebuild from the latest list is retried.
        spdlog::error("Ipv6Firewall::setSplitTunnelingWhitelistIps(), aborted; the filters in place stay, retrying");
        whitelistFilterIds_ = prevFilterIds;
        sync_.onUpdateFailed();
    }
}

bool Ipv6Firewall::applyWhitelistFiltersLocked(HANDLE engineHandle)
{
    if (splitTunnelMode_ == SplitTunnelMode::Disabled || whitelistIps_.empty()) {
        return true;
    }

    // addFilterV6 skips non-v6 entries and no-ops if none remain, so the dual-stack list
    // is passed unfiltered. All ranges are packed into a single filter (OR'd conditions).
    bool ok;
    if (splitTunnelMode_ == SplitTunnelMode::Inclusive) {
        // BLOCK off-tunnel v6 to forced destinations (weight 3): it must fail so apps fall
        // back to v4, which the routes carry into the tunnel. On-tunnel traffic is permitted
        // by the weight-4 tunnel permit.
        ok = Utils::addFilterV6(engineHandle, &whitelistFilterIds_, FWP_ACTION_BLOCK, 3, subLayerGUID_,
                                FIREWALL_SUBLAYER_IPV6_NAMEW, nullptr, &whitelistIps_);
    } else {
        // Exclusive: PERMIT native v6 to excluded destinations for all apps. The callout
        // sublayer's hard BLOCK on the VPN LUID keeps them off the tunnel.
        ok = Utils::addFilterV6(engineHandle, &whitelistFilterIds_, FWP_ACTION_PERMIT, 2, subLayerGUID_,
                                FIREWALL_SUBLAYER_IPV6_NAMEW, nullptr, &whitelistIps_);
    }
    if (!ok) {
        spdlog::error("Ipv6Firewall::applyWhitelistFiltersLocked(), addFilterV6 failed (mode={})", (int)splitTunnelMode_);
    }
    return ok;
}

bool Ipv6Firewall::removeWhitelistFiltersLocked(HANDLE engineHandle)
{
    const bool isRemoved = scoped_permits::deleteRecordedFilters(whitelistFilterIds_, [&](UINT64 id) {
        const DWORD ret = FwpmFilterDeleteById0(engineHandle, id);
        if (ret == ERROR_SUCCESS) {
            return scoped_permits::DeleteResult::kDeleted;
        }
        if (ret == FWP_E_FILTER_NOT_FOUND) {
            return scoped_permits::DeleteResult::kNotFound;
        }
        spdlog::error("Ipv6Firewall::removeWhitelistFiltersLocked(), FwpmFilterDeleteById0 failed: {}", ret);
        return scoped_permits::DeleteResult::kFailed;
    });
    whitelistFilterIds_.clear();  // the caller puts them back if it aborts
    return isRemoved;
}

bool Ipv6Firewall::addFilters(HANDLE engineHandle, bool allowLanTraffic, bool isCustomConfig, bool &arePermitsComplete)
{
    // false if a block is missing; arePermitsComplete false if a permit is (it only blocks more, and
    // is retried).
    bool areBlocksAdded = true;
    AdaptersInfo ai;
    std::vector<NET_IFINDEX> taps = ai.getTAPAdapters();

    // add block filter for all IPv6
    bool ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_BLOCK, 0, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW);
    if (!ret) {
        spdlog::error("Ipv6Firewall::addFilters(), FwpmFilterAdd0 failed");
        areBlocksAdded = false;
    }

    // add permit filter IPv6 for TAP-adapters, but only when the tunnel actually carries a routable
    // (non-link-local) v6 address — mirrors the macOS/Linux hasV6Addr gate and the main FirewallFilter
    // sublayer, so v6 isn't permitted on a v4-only tunnel.
    for (std::vector<NET_IFINDEX>::iterator it = taps.begin(); it != taps.end(); ++it) {
        if (!ai.hasNonLinkLocalV6(*it)) {
            continue;
        }
        NET_LUID luid;
        NETIO_STATUS luidStatus = ConvertInterfaceIndexToLuid(*it, &luid);
        if (luidStatus != NO_ERROR) {
            // No permit with an unknown interface: the adapter is skipped (its IPv6 stays blocked) and
            // the rebuild is retried, by when it may be known.
            spdlog::error("Ipv6Firewall::addFilters(), ConvertInterfaceIndexToLuid failed for ifIndex {}: {}; retrying", *it, luidStatus);
            arePermitsComplete = false;
            continue;
        }

        ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 0, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW, &luid);
        if (!ret) {
            spdlog::error("Ipv6Firewall::addFilters(), add permit filter failed");
            arePermitsComplete = false;
        }
    }

    // add permit filter for ipv6 localhost address
    const std::vector<types::IpAddressRange> localhost = { types::IpAddressRange("::1/128") };
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW, nullptr, &localhost);
    if (!ret) {
        spdlog::error("Could not add IPv6 localhost allow filter");
        arePermitsComplete = false;
    }

    // Always permit link-local: mDNS/discovery responses arrive from fe80:: sources. FirewallFilter
    // already permits fe80::/10 in its sublayer, but the block-all above is a hard block
    // (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) and a hard block in any sublayer wins across sublayers
    // in WFP, so this sublayer must permit it too.
    const std::vector<types::IpAddressRange> linkLocal = { types::IpAddressRange("fe80::/10") };
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW, nullptr, &linkLocal);
    if (!ret) {
        spdlog::error("Could not add IPv6 link-local allow filter");
        arePermitsComplete = false;
    }

    // ICMPv6 NDP/MLD (types 130-137, 143): permit by type so neighbor/router discovery and
    // multicast-listener messages keep working even while IPv6 is otherwise blocked here. The
    // block-all above is a hard block (CLEAR_ACTION_RIGHT) that wins across sublayers, so these must
    // be permitted in this sublayer too. Weight 4, matching the other permits here, and mirroring
    // the main FirewallFilter sublayer.
    ret = Utils::addPermitFilterV6IcmpTypeRange(engineHandle, 130, 137, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW);
    if (!ret) {
        spdlog::error("Could not add ICMPv6 NDP/MLD (130-137) allow filter (ipv6 sublayer)");
        arePermitsComplete = false;
    }
    ret = Utils::addPermitFilterV6IcmpTypeRange(engineHandle, 143, 143, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW);
    if (!ret) {
        spdlog::error("Could not add ICMPv6 MLDv2 (143) allow filter (ipv6 sublayer)");
        arePermitsComplete = false;
    }

    // Permit LAN v6 (ULA + multicast) per the Allow LAN setting; custom configs need private
    // ranges allowed so third-party gateways/DNS work. No tunnel carve-out is needed here:
    // FirewallFilter's tunnel-scoped hard block for these ranges wins across sublayers.
    if (allowLanTraffic || isCustomConfig) {
        const std::vector<types::IpAddressRange> lanV6 = { types::IpAddressRange("fc00::/7"), types::IpAddressRange("ff00::/8") };
        ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW, nullptr, &lanV6);
        if (!ret) {
            spdlog::error("Could not add IPv6 LAN traffic allow filter");
            arePermitsComplete = false;
        }
    }

    // Inclusive split tunneling: non-included apps must keep native ISP IPv6 (v4 parity),
    // while tunnel-bound apps stay restricted to the tunnel.
    if (splitTunnelMode_ == SplitTunnelMode::Inclusive) {
        // Permit all v6 (weight 2, above the block-all) — restores native v6 for non-included apps.
        ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW);
        if (!ret) {
            spdlog::error("Could not add IPv6 inclusive ST permit filter");
            arePermitsComplete = false;
        }

        if (splitTunnelAppsIds_.count() > 0) {
            // Block tunnel-bound apps' v6 (weight 3): if the tunnel has no v6, their v6 must fail
            // so they fall back to v4, which the callout redirects into the tunnel. Loses to the
            // weight-4 permits above (localhost, link-local, NDP, LAN) and the tunnel permit below.
            ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_BLOCK, 3, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW,
                                     nullptr, nullptr, 0, 0, &splitTunnelAppsIds_);
            if (!ret) {
                spdlog::error("Could not add IPv6 inclusive ST apps block filter");
                areBlocksAdded = false;
            }

            // Permit tunnel LUID at weight 4 so redirected apps' tunnel v6 beats the block above
            // (the base tunnel permit is at weight 0).
            for (std::vector<NET_IFINDEX>::iterator it = taps.begin(); it != taps.end(); ++it) {
                if (!ai.hasNonLinkLocalV6(*it)) {
                    continue;
                }
                NET_LUID luid;
                NETIO_STATUS luidStatus = ConvertInterfaceIndexToLuid(*it, &luid);
                if (luidStatus != NO_ERROR) {
                    spdlog::error("Ipv6Firewall::addFilters(), ConvertInterfaceIndexToLuid failed for ifIndex {}: {}; retrying", *it, luidStatus);
                    arePermitsComplete = false;
                    continue;
                }

                ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 4, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW, &luid);
                if (!ret) {
                    spdlog::error("Could not add IPv6 inclusive ST tunnel permit filter");
                    arePermitsComplete = false;
                }
            }
        }
    }

    // Exclusive split tunneling: excluded apps use native ISP IPv6 (the callout redirects
    // them off-tunnel; the callout sublayer's hard blocks on the VPN LUID still prevent
    // their v6 from entering the tunnel when no redirect is possible).
    if (splitTunnelMode_ == SplitTunnelMode::Exclusive && splitTunnelAppsIds_.count() > 0) {
        ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_IPV6_NAMEW,
                                 nullptr, nullptr, 0, 0, &splitTunnelAppsIds_);
        if (!ret) {
            spdlog::error("Could not add IPv6 exclusive ST apps permit filter");
            arePermitsComplete = false;
        }
    }

    // Per-destination filters for the split tunneling IP/hostname list (blocks in inclusive mode,
    // permits in exclusive mode).
    if (!applyWhitelistFiltersLocked(engineHandle)) {
        if (splitTunnelMode_ == SplitTunnelMode::Inclusive) {
            areBlocksAdded = false;
        } else {
            arePermitsComplete = false;
        }
    }
    return areBlocksAdded;
}
