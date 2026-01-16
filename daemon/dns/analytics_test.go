package dns

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/NordSecurity/nordvpn-linux/events"
	mockevents "github.com/NordSecurity/nordvpn-linux/test/mock/events"
	"github.com/stretchr/testify/assert"
)

func Test_emitResolvConfOverwrittenEvent(t *testing.T) {
	mockPublisher := mockevents.MockPublisher[events.DebuggerEvent]{}
	analytics := newDNSAnalytics(&mockPublisher)
	analytics.emitResolvConfOverwrittenEvent()

	event, n, stackIsEmpty := mockPublisher.PopEvent()

	assert.True(t, stackIsEmpty, "Event not emitted.")
	assert.Equal(t, 0, n, "Unexpected number of events emitted.")
	assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
		Path:  debuggerEventBaseKey + "." + debuggerEventTypeKey,
		Value: resolvConfOverwrittenEventType.String()})
	assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
		Path:  debuggerEventBaseKey + "." + debuggerEventManagementServiceKey,
		Value: unknownService.String()})
	assert.Equal(t,
		"{\"event\":\"resolvconf_overwritten\",\"namespace\":\"nordvpn-linux\",\"management_service\":\"unknown\"}",
		event.JsonData)
}

func Test_emitDNSConfiguredEvent(t *testing.T) {
	tests := []struct {
		name              string
		managementService dnsManagementService
	}{
		{
			name:              "systemd-resolved",
			managementService: systemdResolvedService,
		},
		{
			name:              "unmanaged",
			managementService: unmanagedService,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockPublisher := mockevents.MockPublisher[events.DebuggerEvent]{}
			analytics := newDNSAnalytics(&mockPublisher)
			analytics.setManagementService(test.managementService)
			analytics.emitDNSConfiguredEvent()

			event, n, stackIsEmpty := mockPublisher.PopEvent()

			assert.True(t, stackIsEmpty, "Event not emitted.")
			assert.Equal(t, 0, n, "Unexpected number of events emitted.")
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventTypeKey,
				Value: dnsConfiguredEventType.String()})
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventManagementServiceKey,
				Value: test.managementService.String()})

			expectedJson :=
				fmt.Sprintf("{\"event\":\"dns_configured\",\"namespace\":\"nordvpn-linux\",\"management_service\":\"%s\"}",
					test.managementService.String())
			assert.Equal(t,
				expectedJson,
				event.JsonData)
		})
	}
}

func Test_emidDNSConfigurationErrorEvent(t *testing.T) {
	tests := []struct {
		name              string
		managementService dnsManagementService
		errorType         errorType
		critical          bool
	}{
		{
			name:              "set failed for unmanaged, not critical",
			managementService: unmanagedService,
			errorType:         setFailedErrorType,
			critical:          false,
		},
		{
			name:              "failed to detect for unmanaged, not critical",
			managementService: unmanagedService,
			errorType:         detectionFailedErrorType,
			critical:          false,
		},
		{
			name:              "set failed for unmanaged, critical",
			managementService: unmanagedService,
			errorType:         setFailedErrorType,
			critical:          true,
		},
		{
			name:              "failed to detect for unmanaged, critical",
			managementService: unmanagedService,
			errorType:         detectionFailedErrorType,
			critical:          true,
		},
		{
			name:              "set failed for systemd-resolved, not critical",
			managementService: systemdResolvedService,
			errorType:         detectionFailedErrorType,
			critical:          false,
		},
		{
			name:              "failed to detect for systemd-resolved, not critical",
			managementService: systemdResolvedService,
			errorType:         detectionFailedErrorType,
			critical:          false,
		},
		{
			name:              "set failed for systemd-resolved, critical",
			managementService: systemdResolvedService,
			errorType:         detectionFailedErrorType,
			critical:          true,
		},
		{
			name:              "failed to detect for systemd-resolved, critical",
			managementService: systemdResolvedService,
			errorType:         detectionFailedErrorType,
			critical:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockPublisher := mockevents.MockPublisher[events.DebuggerEvent]{}
			analytics := newDNSAnalytics(&mockPublisher)
			analytics.setManagementService(test.managementService)
			analytics.emitDNSConfigurationErrorEvent(test.errorType, test.critical)

			event, n, stackIsEmpty := mockPublisher.PopEvent()

			assert.True(t, stackIsEmpty, "Event not emitted.")
			assert.Equal(t, 0, n, "Unexpected number of events emitted.")
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventTypeKey,
				Value: dnsConfigurationErrorEventType.String()})
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventManagementServiceKey,
				Value: test.managementService.String()})
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventErrorTypeKey,
				Value: test.errorType.String(),
			})
			assert.Contains(t, event.KeyBasedContextPaths, events.ContextValue{
				Path:  debuggerEventBaseKey + "." + debuggerEventCriticalKey,
				Value: test.critical,
			})

			expectedJson :=
				fmt.Sprintf("{\"event\":\"dns_configuration_error\",\"namespace\":\"nordvpn-linux\",\"management_service\":\"%s\",\"error_type\":\"%s\",\"cricital\":%s}",
					test.managementService.String(),
					test.errorType.String(),
					strconv.FormatBool(test.critical))
			assert.Equal(t,
				expectedJson,
				event.JsonData)
		})
	}
}
