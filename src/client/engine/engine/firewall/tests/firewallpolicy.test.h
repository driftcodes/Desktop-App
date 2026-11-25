#pragma once

#include <QObject>

class TestFirewallPolicy : public QObject
{
    Q_OBJECT

private slots:
    void testNotConnectedExceptionsUnderProxy();
    void testNotConnectedExceptionsWithoutProxy();
    void testLeaveConnectionForgetsEndpointAndKeepsFirewallOn();
    void testLeaveConnectionLeavesFirewallOff();
    void testAfterConnectedDecision();
    void testProxiedDnsLeakFilterSpansReconnect();
    void testDnsLeakFilterRebuiltOnNetworkChangeWhileConnecting();
    void testDnsLeakFilterUntouchedWithoutProxy();
    void testFirstConnectHeldUntilBlockConfirmed();
    void testStaleRetryDoesNotUndoUnproxiedSession();
    void testReconnectNeedsNotConnectedRules();
    void testLocationSwitchFromUnproxiedKeepsNewRules();
    void testNewUnproxiedSessionAfterErrorTakesOverFilter();
    void testProxiedRequestReplacingAttemptStillConnecting();
    void testDirectRequestReplacingProxiedSession();
    void testRequestKeepsProxyChosenAtSelection();
    void testDroppedHandOverHoldsDirectAttempt();
    void testEngineTrafficKeepsRequestProxy();
    void testDirectConnectorNeedsItsOwnRules();
    void testLocationSwitchAppliesNewRequestProxy();
    void testConnectedReportedOnlyWithConnectedRules();
    void testLostHandOverReplyReclaimsFilter();
    void testSecondFailedHandOverBeforeReclaimKeepsRules();
    void testIgnoredConnectorRequestIsNotInstalled();
    void testRetryBacksOffAndStopsOnSuccess();
    void testDnsLeakFilterKeptAfterErrorUntilFirewallOff();
};
