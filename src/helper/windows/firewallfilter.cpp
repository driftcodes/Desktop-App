#include <Windows.h>
#include <Fwpmu.h>

#include <spdlog/spdlog.h>

#include "firewallfilter.h"
#include "utils.h"
#include "adapters_info.h"
#include "scoped_permit_plan.h"


FirewallFilter::FirewallFilter(FwpmWrapper &fwpmWrapper) :
    fwpmWrapper_(fwpmWrapper), lastAllowLocalTraffic_(false)
{
    UuidFromString((RPC_WSTR)UUID_LAYER, &subLayerGUID_);
}

void FirewallFilter::release()
{
}

bool FirewallFilter::on(const wchar_t *connectingIp, const std::vector<std::wstring> &ips, const std::vector<std::wstring> &windscribeOnlyIps,
                        bool bAllowLocalTraffic, bool bIsCustomConfig, bool bHoldLanPermit)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();

    // One transaction: the old rules out and the new in, committed only with both default blocks
    // added (scoped_permits::planFirewallApply); otherwise aborted, so the rules in place stay.
    const bool hasBegun = fwpmWrapper_.beginTransaction();
    if (!hasBegun) {
        spdlog::error("FirewallFilter::on(), could not begin the transaction; the rules in place stay");
        fwpmWrapper_.unlock();
        return false;
    }
    // offImpl/addFilters replace the recorded split-tunnel filter ids; kept as they were unless this
    // commits (Windows keeps the old filters then).
    scoped_permits::FilterIdsSnapshot<std::vector<UINT64>> ids({&filterIdsApps_, &filterIdsSplitRoutingIps_});

    if (currentStatusImpl(hEngine) == true) {
        offImpl(hEngine);
    }

    FWPM_SUBLAYER0 subLayer = {0};
    subLayer.subLayerKey = subLayerGUID_;
    subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_NAMEW;
    subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_NAMEW;
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    subLayer.weight = 0xFFFF;

    bool areDefaultBlocksAdded[2] = {false, false};
    bool areOtherRulesComplete = false;
    bool isSplitTunnelComplete = false;
    DWORD dwRet = FwpmSubLayerAdd0(hEngine, &subLayer, NULL );
    if (dwRet == ERROR_SUCCESS) {
        areOtherRulesComplete = addFilters(hEngine, connectingIp, ips, windscribeOnlyIps, bAllowLocalTraffic, bIsCustomConfig,
                                           bHoldLanPermit, areDefaultBlocksAdded, &isSplitTunnelComplete);
    } else {
        spdlog::error("FirewallFilter::on(), FwpmSubLayerAdd0 failed: {}", dwRet);
    }

    const auto plan = scoped_permits::planFirewallApply(hasBegun, areDefaultBlocksAdded[0], areDefaultBlocksAdded[1],
                                                         areOtherRulesComplete);
    bool isComplete = false;
    if (plan.commit) {
        const bool isCommitted = fwpmWrapper_.endTransaction();
        if (!isCommitted) {
            spdlog::error("FirewallFilter::on(), commit failed; the rules in place stay");
            ids.rollback();
        } else {
            // The split-tunnel filters now follow the latest request (rebuilt by the retry if a
            // permit is missing).
            splitTunnel_.onFirewallRebuilt(isSplitTunnelComplete);
        }
        isComplete = isCommitted && plan.isComplete;
    } else {
        spdlog::error("FirewallFilter::on(), a default block could not be added (v4 {}, v6 {}); aborted, the rules in place stay",
                      areDefaultBlocksAdded[0], areDefaultBlocksAdded[1]);
        fwpmWrapper_.abortTransaction();
        ids.rollback();
    }
    fwpmWrapper_.unlock();
    return isComplete;
}

bool FirewallFilter::addLinkLocalDnsBlock(HANDLE engineHandle)
{
    // IPv6 link-local stays permitted (weight 8) whatever the LAN setting, for neighbor discovery and
    // the like; DNS to it is not, while the DNS baseline is missing. Weight 9: above that permit.
    const std::vector<types::IpAddressRange> linkLocalV6 = { types::IpAddressRange("fe80::/10") };
    const bool ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_BLOCK, 9, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW,
                                        nullptr, &linkLocalV6, 0, 53);
    if (!ret) {
        spdlog::error("Could not add the IPv6 link-local DNS block");
    }
    return ret;
}

bool FirewallFilter::holdLanPermit()
{
    // Service start, the firewall kept from before and no DNS baseline: without the client's request
    // the rules cannot be rebuilt, so remove the LAN permits (the weight-4 permits are exactly those)
    // and block DNS to IPv6 link-local. The client's next firewallOn rebuilds everything.
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    bool isHeld = fwpmWrapper_.beginTransaction();
    if (isHeld) {
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        std::vector<UINT64> lanPermits;
        for (const GUID &layer : layers) {
            FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate;
            ZeroMemory(&enumTemplate, sizeof(enumTemplate));
            enumTemplate.layerKey = layer;
            enumTemplate.actionMask = 0xFFFFFFFF;
            HANDLE enumHandle = NULL;
            if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) != ERROR_SUCCESS) {
                isHeld = false;
                continue;
            }
            FWPM_FILTER0 **filters = nullptr;
            UINT32 count = 0;
            DWORD enumRet = ERROR_SUCCESS;
            while ((enumRet = FwpmFilterEnum0(hEngine, enumHandle, INFINITE, &filters, &count)) == ERROR_SUCCESS && count > 0) {
                for (UINT32 k = 0; k < count; ++k) {
                    const FWPM_FILTER0 &f = *filters[k];
                    if (f.subLayerKey == subLayerGUID_ && f.action.type == FWP_ACTION_PERMIT &&
                        f.weight.type == FWP_UINT8 && f.weight.uint8 == 4) {
                        lanPermits.push_back(f.filterId);
                    }
                }
                FwpmFreeMemory0((void **)&filters);
            }
            if (enumRet != ERROR_SUCCESS) {
                // Not the end of the list: an error, so a LAN permit may have been missed.
                spdlog::error("FirewallFilter::holdLanPermit(), FwpmFilterEnum0 failed: {}", enumRet);
                isHeld = false;
            }
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        }
        for (const UINT64 id : lanPermits) {
            if (FwpmFilterDeleteById0(hEngine, id) != ERROR_SUCCESS) {
                isHeld = false;
            }
        }
        isHeld = isHeld && addLinkLocalDnsBlock(hEngine);
        if (isHeld) {
            isHeld = fwpmWrapper_.endTransaction();
        } else {
            fwpmWrapper_.abortTransaction();
        }
        spdlog::info("FirewallFilter::holdLanPermit(): {} LAN permit filter(s), held: {}", lanPermits.size(), isHeld);
    }
    fwpmWrapper_.unlock();
    return isHeld;
}

void FirewallFilter::off()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    if (runTransaction([&]() { offImpl(hEngine); return true; })) {
        splitTunnel_.onFirewallOff();
    }
    fwpmWrapper_.unlock();
}

bool FirewallFilter::runTransaction(const std::function<bool()> &body)
{
    scoped_permits::FilterIdsSnapshot<std::vector<UINT64>> ids({&filterIdsApps_, &filterIdsSplitRoutingIps_});
    if (!fwpmWrapper_.beginTransaction()) {
        spdlog::error("FirewallFilter: could not begin a transaction; nothing changed");
        return false;
    }
    if (!body()) {
        // A filter could not be deleted (it may still be in force) or added: commit nothing.
        spdlog::error("FirewallFilter: a step failed; aborted, the filters in place (and their recorded ids) stay");
        fwpmWrapper_.abortTransaction();
        ids.rollback();
        return false;
    }
    if (fwpmWrapper_.endTransaction()) {
        return true;
    }
    spdlog::error("FirewallFilter: commit failed; the filters in place (and their recorded ids) stay");
    fwpmWrapper_.abortTransaction();
    ids.rollback();
    return false;
}

void FirewallFilter::retryPendingSplitTunnelUpdate()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!splitTunnel_.isPending()) {
        return;
    }
    spdlog::info("FirewallFilter: retrying the split-tunnel filters, not yet in line with the latest settings");
    syncSplitTunnelFilters();
}

bool FirewallFilter::currentStatus()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    bool bRet = currentStatusImpl(hEngine);
    fwpmWrapper_.unlock();
    return bRet;
}

bool FirewallFilter::currentStatusImpl(HANDLE engineHandle)
{
    return firewallStatusImpl(engineHandle) == scoped_permits::FirewallStatus::kOn;
}

scoped_permits::FirewallStatus FirewallFilter::firewallStatusImpl(HANDLE engineHandle)
{
    FWPM_SUBLAYER0 *subLayer;
    DWORD dwRet = FwpmSubLayerGetByKey0(engineHandle, &subLayerGUID_, &subLayer);
    if (dwRet == ERROR_SUCCESS) {
        FwpmFreeMemory0((void **)&subLayer);
        return scoped_permits::FirewallStatus::kOn;
    }
    if (dwRet == FWP_E_SUBLAYER_NOT_FOUND) {
        return scoped_permits::FirewallStatus::kOff;
    }
    spdlog::error("FirewallFilter::firewallStatusImpl(), FwpmSubLayerGetByKey0 failed: {}", dwRet);
    return scoped_permits::FirewallStatus::kUnknown;
}

void FirewallFilter::offImpl(HANDLE engineHandle)
{
    if (Utils::deleteSublayerAndAllFilters(engineHandle, &subLayerGUID_)) {
        spdlog::info("FirewallFilter::offImpl(), all filters deleted");
    } else {
        spdlog::error("FirewallFilter::offImpl(), failed delete filters");
    }
    filterIdsApps_.clear();
    filterIdsSplitRoutingIps_.clear();
}

void FirewallFilter::syncSplitTunnelFilters()
{
    // Called with mutex_ held. Brings the split-tunnel filters in line with the latest combined
    // request (mode, apps, IPs), whichever setter changed it; a failure leaves the filters in place
    // as they were and the request pending (retryPendingSplitTunnelUpdate).
    HANDLE hEngine = fwpmWrapper_.getHandleAndLock();
    const scoped_permits::SplitTunnelStep step = splitTunnel_.step(firewallStatusImpl(hEngine));
    if (step == scoped_permits::SplitTunnelStep::kFirewallOff) {
        // No firewall sublayer, so none of its filters; the next on() builds them.
        filterIdsApps_.clear();
        filterIdsSplitRoutingIps_.clear();
    } else if (step == scoped_permits::SplitTunnelStep::kRetryLater) {
        spdlog::error("FirewallFilter: the firewall's state could not be read; the split-tunnel update stays pending");
    } else if (step == scoped_permits::SplitTunnelStep::kApply) {
        const bool isDone = runTransaction([&]() {
            return removeAllSplitTunnelingFilters(hEngine) && addSplitTunnelingFilters(hEngine);
        });
        if (isDone) {
            splitTunnel_.onApplied();
        } else {
            spdlog::error("FirewallFilter: split-tunnel filter update failed; the filters in place stay, retried");
            splitTunnel_.onFailed();
        }
    }
    fwpmWrapper_.unlock();
}

void FirewallFilter::setSplitTunnelingEnabled(bool isExclusiveMode)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto &request = splitTunnel_.request();
    request.isEnabled = true;
    request.isExclusive = isExclusiveMode;
    syncSplitTunnelFilters();
}

void FirewallFilter::setSplitTunnelingDisabled()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    splitTunnel_.request().isEnabled = false;
    syncSplitTunnelFilters();
}

void FirewallFilter::setWindscribeAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    windscribeAppsIds_ = appsIds;
}

void FirewallFilter::setVpnAppsIds(const AppsIds &appsIds)
{
    // Only used for the connecting IP's permit, which on() builds; the split-tunnel filters do not
    // depend on it.
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    vpnAppsIds_ = appsIds;
}

void FirewallFilter::setSplitTunnelingAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    splitTunnel_.request().apps = appsIds;
    syncSplitTunnelFilters();
}

void FirewallFilter::setSplitTunnelingWhitelistIps(const std::vector<types::IpAddressRange> &ips)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    splitTunnel_.request().ips = ips;
    syncSplitTunnelFilters();
}

bool FirewallFilter::addFilters(HANDLE engineHandle, const wchar_t *connectingIp, const std::vector<std::wstring> &ips,
                                const std::vector<std::wstring> &windscribeOnlyIps, bool bAllowLocalTraffic, bool bIsCustomConfig,
                                bool bHoldLanPermit, bool areDefaultBlocksAdded[2], bool *isSplitTunnelComplete)
{
    // false when a permit the caller asked for is missing (the firewall is still on, blocking more).
    bool isComplete = true;
    AdaptersInfo ai;
    std::vector<NET_IFINDEX> taps = ai.getTAPAdapters();

    // add block filter for all IPs, for all adapters, IPv4.
    bool ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_BLOCK, 0, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW);
    areDefaultBlocksAdded[0] = ret;
    if (!ret) {
        spdlog::error("Could not add IPv4 block filter");
    }
    // add block filter for all IPs, for all adapters, IPv6.
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_BLOCK, 0, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW);
    areDefaultBlocksAdded[1] = ret;
    if (!ret) {
        spdlog::error("Could not add IPv6 block filter");
    }

    // The per-interface (tunnel-scoped) filters in this loop are added with persistent=false: they
    // are runtime-only and must NOT survive into the firewall-on-boot persisted ruleset, which should
    // be the curated minimal set (default block + server IPs + DHCP + loopback + link-local + NDP/MLD
    // + LAN carve-outs + the reserved-DNS block, all left persistent). The connecting-IP and
    // split-tunnel permits below are non-persistent for the same reason.
    // add permit filter for TAP-adapters
    for (std::vector<NET_IFINDEX>::iterator it = taps.begin(); it != taps.end(); ++it) {
        NET_LUID luid;
        NETIO_STATUS luidRet = ConvertInterfaceIndexToLuid(*it, &luid);
        if (luidRet != NO_ERROR) {
            spdlog::error("FirewallFilter::addFilters(), ConvertInterfaceIndexToLuid failed for ifIndex {}: {}", *it, luidRet);
        }

        // Always allow 10.255.255.0/24 (Windscribe reserved) regardless of custom config,
        // because the Allow LAN flag later blocks the entire 10/8 range
        const std::vector<types::IpAddressRange> reserved = { types::IpAddressRange("10.255.255.0/24") };
        ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, &luid, &reserved, 0, 0, nullptr, false);
        if (!ret) {
            spdlog::error(L"Could not add reserved allow filter on VPN interface");
        }

        if (!bIsCustomConfig) {
            // We want to allow access to local VPN interface addresses regardless of which interface the packet will go through, not just a VPN interface
            const std::vector<types::IpAddressRange> localAddrs = types::IpAddressRange::fromStrings(ai.getAdapterAddresses(*it));
            if (!localAddrs.empty()) {
                ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &localAddrs, 0, 0, nullptr, false);
                if (!ret) {
                    spdlog::error("Could not add reserved allow filter on private address for VPN interface");
                }
            }
            // Carve-out (LAN-into-tunnel blocks): only needed when "Allow LAN traffic" is on. With
            // LAN off, the weight-4 global LAN block already outranks the weight-1 tunnel permit, so
            // these weight-6 blocks would be redundant. Gated on bAllowLocalTraffic to match the
            // macOS/Linux runtime rulesets and avoid emitting dead rules.
            if (bAllowLocalTraffic) {
                // Disallow all other private, link-local, loopback networks from going over tunnel
                const std::vector<types::IpAddressRange> priv = types::IpAddressRange::fromStrings(
                    {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"});
                ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_BLOCK, 6, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, &luid, &priv, 0, 0, nullptr, false);
                if (!ret) {
                    spdlog::error("Could not add private network block filter on VPN interface");
                }

                // Same carve-out for IPv6: LAN-destined ULA/multicast must not enter the (dual-stack)
                // tunnel. Weight 6 outweighs the unscoped weight-4 LAN permits and the weight-1 tunnel
                // permit, so these ranges are dropped on the tunnel but still pass on the physical NIC.
                const std::vector<types::IpAddressRange> privV6 = { types::IpAddressRange("fc00::/7"), types::IpAddressRange("ff00::/8") };
                ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_BLOCK, 6, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, &luid, &privV6, 0, 0, nullptr, false);
                if (!ret) {
                    spdlog::error("Could not add private network IPv6 block filter on VPN interface");
                }
            }
        }

        // Allow other IPv4 traffic on this interface
        ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 1, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, &luid, nullptr, 0, 0, nullptr, false);
        if (!ret) {
            spdlog::error("Could not add IPv4 allow filter on VPN interface");
        }
        // Allow IPv6 traffic on this interface, but only when the tunnel actually carries a routable
        // (non-link-local) v6 address — mirrors the macOS/Linux hasV6Addr gate (probeInterfaceAddresses)
        // so v6 isn't blanket-permitted on a v4-only tunnel.
        if (ai.hasNonLinkLocalV6(*it)) {
            ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 1, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, &luid, nullptr, 0, 0, nullptr, false);
            if (!ret) {
                spdlog::error("Could not add IPv6 allow filter on VPN interface");
            }
        }
    }

    // add permit filter for split tunneling app ids and ips (the latest request)
    // A missing split-tunnel permit fails closed (the excluded app is blocked); reported incomplete
    // and rebuilt by retryPendingSplitTunnelUpdate().
    *isSplitTunnelComplete = addSplitTunnelingFilters(engineHandle);
    if (!*isSplitTunnelComplete) {
        isComplete = false;
    }

    addPermitFilterForVpnAndSystemServices(engineHandle, connectingIp);

    // add permit filter for specific IPs
    for (size_t i = 0; i < ips.size(); ++i) {
        const std::vector<types::IpAddressRange> ipAddr = { types::IpAddressRange(ips[i]) };
        ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &ipAddr);
        if (!ret) {
            spdlog::error("Could not add " WS_PRODUCT_NAME " IPs allow filter");
        }
    }

    // Addresses only Windscribe's own programs may reach (the DNS servers while not connected through a
    // proxy). Any port, like the filter above, but only for these applications: another program's
    // ordinary DNS or DNS-over-HTTPS to them is blocked. Throne and other excluded apps keep their own
    // split-tunnel permit. If the programs could not be identified, no permit is added at all (a
    // permit without a program condition would apply to every program); the rest of the firewall
    // stays on and on() reports the failure.
    const std::vector<std::wstring> scopedIps = scoped_permits::windscribeOnlyPermits(windscribeOnlyIps, windscribeAppsIds_.count());
    if (!windscribeOnlyIps.empty() && scopedIps.empty()) {
        spdlog::error("FirewallFilter: Windscribe programs unknown, not permitting {} DNS server(s) for any program",
                      windscribeOnlyIps.size());
        isComplete = false;
    }
    for (const auto &ip : scopedIps) {
        const std::vector<types::IpAddressRange> ipAddr = { types::IpAddressRange(ip) };
        ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr,
                                 &ipAddr, 0, 0, &windscribeAppsIds_);
        if (!ret) {
            spdlog::error("Could not add " WS_PRODUCT_NAME "-only IPs allow filter");
            isComplete = false;
        }
    }

    // add permit filter for DHCP.
    // Weight must be higher than the LAN block below (weight 4): DHCP lease renewal is unicast to
    // the DHCP server, which usually lives in a private range. With a lower weight the veto LAN
    // block would override this permit when "Allow LAN" is off, breaking renewal and dropping Wi-Fi.
    ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 5, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 68);
    if (!ret) {
        spdlog::error("Could not add DHCP allow filter (68)");
    }
    // add permit filter for DHCP
    ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 5, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 67);
    if (!ret) {
        spdlog::error("Could not add DHCP allow filter (67)");
    }

    // DHCPv6 (client port 546, server port 547)
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 5, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 546);
    if (!ret) {
        spdlog::error("Could not add DHCPv6 allow filter (546)");
    }
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 5, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 547);
    if (!ret) {
        spdlog::error("Could not add DHCPv6 allow filter (547)");
    }

    // Always allow localhost
    const std::vector<types::IpAddressRange> localhostV4 = { types::IpAddressRange("127.0.0.0/8") };
    ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &localhostV4);
    if (!ret) {
        spdlog::error("Could not add localhost v4 allow filter");
    }
    const std::vector<types::IpAddressRange> localhostV6 = { types::IpAddressRange("::1/128") };
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &localhostV6);
    if (!ret) {
        spdlog::error("Could not add localhost v6 allow filter.");
    }

    // Always allow IPv6 link-local (required for neighbor discovery, Apple Continuity, etc.)
    const std::vector<types::IpAddressRange> linkLocalV6 = { types::IpAddressRange("fe80::/10") };
    ret = Utils::addFilterV6(engineHandle, nullptr, FWP_ACTION_PERMIT, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &linkLocalV6);
    if (!ret) {
        spdlog::error("Could not add IPv6 link-local allow filter.");
    }

    // ICMPv6 NDP/MLD (types 130-137, 143): always permit, independent of the Allow LAN setting, so
    // neighbor/router discovery and multicast-listener messages keep working even when LAN traffic
    // is blocked. NS/RS and MLD reports use ff02:: multicast destinations that would otherwise be
    // caught by the gated ff00::/8 rule (block when LAN off) or the weight-0 block-all. Weight 8,
    // like the other always-on essentials. Mirrors the Linux/macOS rulesets.
    ret = Utils::addPermitFilterV6IcmpTypeRange(engineHandle, 130, 137, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW);
    if (!ret) {
        spdlog::error("Could not add ICMPv6 NDP/MLD (130-137) allow filter.");
    }
    ret = Utils::addPermitFilterV6IcmpTypeRange(engineHandle, 143, 143, 8, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW);
    if (!ret) {
        spdlog::error("Could not add ICMPv6 MLDv2 (143) allow filter.");
    }

    // add permit/block filters for Local Network.
    // We explicitly block if not allowed, since this setting should take precedence over split tunneling filters.
    // Custom configs need private ranges allowed so third-party VPN DNS/gateway/routes work.
    // Held back while the DNS baseline is not in place: the LAN permit would let any program query a
    // router's DNS.
    bool bAllowLan = (bAllowLocalTraffic || bIsCustomConfig) && !bHoldLanPermit;
    if (bHoldLanPermit && !addLinkLocalDnsBlock(engineHandle)) {
        isComplete = false;
    }
    const std::vector<types::IpAddressRange> privV4 = types::IpAddressRange::fromStrings(
        {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"});
    ret = Utils::addFilterV4(engineHandle, nullptr, bAllowLan ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, 4, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &privV4);
    if (!ret) {
        spdlog::error("Could not add IPv4 LAN traffic allow/block filter.");
    }

    // 10.255.255.0/24 (in-tunnel WG DNS): always blocked off the tunnel, regardless of the Allow LAN
    // setting. The weight-8 reserved permit on the VPN adapter (above) keeps it reachable in-tunnel;
    // this weight-5 block outranks the weight-4 LAN rule (so it drops on the physical NIC) but is
    // outranked by the weight-8 tunnel permit. Matches the Linux/macOS "tunnel pass, physical block".
    const std::vector<types::IpAddressRange> reservedDns = { types::IpAddressRange("10.255.255.0/24") };
    ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_BLOCK, 5, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &reservedDns);
    if (!ret) {
        spdlog::error("Could not add reserved in-tunnel DNS block filter.");
    }

    // add permit/block filters for multicast
    const std::vector<types::IpAddressRange> multicastV4 = { types::IpAddressRange("224.0.0.0/4") };
    ret = Utils::addFilterV4(engineHandle, nullptr, bAllowLan ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, 4, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &multicastV4);
    if (!ret) {
        spdlog::error("Could not add IPv4 multicast allow/block filter.");
    }

    const std::vector<types::IpAddressRange> multicastV6 = { types::IpAddressRange("ff00::/8") };
    ret = Utils::addFilterV6(engineHandle, nullptr, bAllowLan ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, 4, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &multicastV6);
    if (!ret) {
        spdlog::error("Could not add IPv6 multicast allow/block filter.");
    }

    // IPv6 ULA (the v6 analogue of the private v4 ranges above). NOTE (#1687): while connected the
    // Ipv6Firewall sublayer (ipv6_firewall.cpp) gates LAN v6 too, with the same allowLan condition,
    // so the two sublayers must be kept in sync.
    const std::vector<types::IpAddressRange> ulaV6 = { types::IpAddressRange("fc00::/7") };
    ret = Utils::addFilterV6(engineHandle, nullptr, bAllowLan ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, 4, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &ulaV6);
    if (!ret) {
        spdlog::error("Could not add IPv6 ULA LAN traffic allow/block filter.");
    }
    return isComplete;
}

void FirewallFilter::addPermitFilterForVpnAndSystemServices(HANDLE engineHandle, const wchar_t *connectingIp)
{
    int ret = 0;

    AppsIds allowedIds;
    std::wstring svchost = Utils::getSystemDir() + L"\\svchost.exe";

    allowedIds.setFromList({svchost, L"System"});
    allowedIds.addFrom(vpnAppsIds_);

    // add allow filter for connecting IP (IPv4-only — connectingIp is always IPv4)
    const std::vector<types::IpAddressRange> connectingIpAddr = { types::IpAddressRange(connectingIp) };
    ret = Utils::addFilterV4(engineHandle, nullptr, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &connectingIpAddr, 0, 0, &allowedIds, false);
    if (!ret) {
        spdlog::error("Could not add connecting IP allow filter");
    }
}

bool FirewallFilter::addSplitTunnelingFilters(HANDLE engineHandle)
{
    const auto &requested = splitTunnel_.requested();
    if (!requested.isEnabled) {
        return true;
    }
    const bool isAppsAdded = addPermitFilterForAppsIds(engineHandle);
    const bool isIpsAdded = addPermitFilterForSplitRoutingWhitelistIps(engineHandle);
    return isAppsAdded && isIpsAdded;
}

bool FirewallFilter::addPermitFilterForAppsIds(HANDLE engineHandle)
{
    const auto &requested = splitTunnel_.requested();
    bool ret = true;
    if (requested.isExclusive) {
        if (requested.apps.count() > 0) {
            AppsIds apps = requested.apps;
            ret = Utils::addFilterV4(engineHandle, &filterIdsApps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 0, 0, &apps, false);
            ret = Utils::addFilterV6(engineHandle, &filterIdsApps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 0, 0, &apps, false) && ret;
        }
    } else {
        ret = Utils::addFilterV4(engineHandle, &filterIdsApps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 0, 0, nullptr, false);
        ret = Utils::addFilterV6(engineHandle, &filterIdsApps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, nullptr, 0, 0, nullptr, false) && ret;
    }

    if (!ret) {
        spdlog::error("Could not add split tunnel app filters");
    }
    return ret;
}

bool FirewallFilter::addPermitFilterForSplitRoutingWhitelistIps(HANDLE engineHandle)
{
    const auto &requested = splitTunnel_.requested();
    const std::vector<types::IpAddressRange> &ips = requested.ips;
    if (!requested.isExclusive || ips.empty()) {
        return true;
    }

    // addFilterV4/addFilterV6 internally filter the dual-stack vector by family and become
    // no-ops if no entries of their family are present. Pass the same container to both.
    bool ret = Utils::addFilterV4(engineHandle, &filterIdsSplitRoutingIps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &ips, 0, 0, nullptr, false);
    if (!ret) {
        spdlog::error("Could not add split tunnel IPv4 filters");
    }
    const bool isV4Added = ret;
    ret = Utils::addFilterV6(engineHandle, &filterIdsSplitRoutingIps_, FWP_ACTION_PERMIT, 2, subLayerGUID_, FIREWALL_SUBLAYER_NAMEW, nullptr, &ips, 0, 0, nullptr, false);
    if (!ret) {
        spdlog::error("Could not add split tunnel IPv6 filters");
    }
    return isV4Added && ret;
}

bool FirewallFilter::removeAllSplitTunnelingFilters(HANDLE engineHandle)
{
    const bool isAppsRemoved = removeAppsSplitTunnelingFilter(engineHandle);
    const bool isIpsRemoved = removeIpsSplitTunnelingFilter(engineHandle);
    return isAppsRemoved && isIpsRemoved;
}

namespace {
scoped_permits::DeleteResult deleteFilter(HANDLE engineHandle, UINT64 id, const char *what)
{
    const DWORD ret = FwpmFilterDeleteById0(engineHandle, id);
    if (ret == ERROR_SUCCESS) {
        return scoped_permits::DeleteResult::kDeleted;
    }
    if (ret == FWP_E_FILTER_NOT_FOUND) {
        return scoped_permits::DeleteResult::kNotFound;
    }
    spdlog::error("FirewallFilter: deleting a {} split-tunnel filter failed: {}", what, ret);
    return scoped_permits::DeleteResult::kFailed;
}
} // namespace

bool FirewallFilter::removeAppsSplitTunnelingFilter(HANDLE engineHandle)
{
    // Cleared even on failure: the caller then aborts the transaction and puts the ids back.
    const bool isRemoved = scoped_permits::deleteRecordedFilters(
        filterIdsApps_, [&](UINT64 id) { return deleteFilter(engineHandle, id, "app"); });
    filterIdsApps_.clear();
    return isRemoved;
}

bool FirewallFilter::removeIpsSplitTunnelingFilter(HANDLE engineHandle)
{
    const bool isRemoved = scoped_permits::deleteRecordedFilters(
        filterIdsSplitRoutingIps_, [&](UINT64 id) { return deleteFilter(engineHandle, id, "IP"); });
    filterIdsSplitRoutingIps_.clear();
    return isRemoved;
}
