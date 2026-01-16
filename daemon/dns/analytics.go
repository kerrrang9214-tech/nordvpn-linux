package dns

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/NordSecurity/nordvpn-linux/events"
	"github.com/NordSecurity/nordvpn-linux/internal"
)

var globalPaths = []string{
	"device.*",
	"application.nordvpnapp.*",
	"application.nordvpnapp.version",
	"application.nordvpnapp.platform",
}

const (
	debuggerEventBaseKey              = "dns"
	debuggerEventTypeKey              = "type"
	debuggerEventManagementServiceKey = "management_service"
	debuggerEventErrorTypeKey         = "error_type"
	debuggerEventCriticalKey          = "critical"
)

type event struct {
	Event             string `json:"event"`
	MessageNamespace  string `json:"namespace"`
	ManagementService string `json:"management_service"`
}

func newEvent(eventType eventType, messageNamespace string, managementService dnsManagementService) event {
	return event{
		Event:             eventType.String(),
		MessageNamespace:  internal.DebugEventMessageNamespace,
		ManagementService: managementService.String(),
	}

}

func (e event) toContextPaths() []events.ContextValue {
	return []events.ContextValue{
		{
			Path:  debuggerEventBaseKey + "." + debuggerEventTypeKey,
			Value: e.Event,
		},
		{
			Path:  debuggerEventBaseKey + "." + debuggerEventManagementServiceKey,
			Value: e.ManagementService,
		},
	}
}

func (e event) toDebuggerEvent() *events.DebuggerEvent {
	jsonData, err := json.Marshal(e)
	if err != nil {
		log.Println(internal.DebugPrefix, dnsPrefix, "failed to serialize event json for resovl.conf overwrite:", err)
		jsonData = []byte("{}")
	}

	debuggerEvent := events.NewDebuggerEvent(string(jsonData)).
		WithKeyBasedContextPaths(e.toContextPaths()...).
		WithGlobalContextPaths(globalPaths...)

	return debuggerEvent
}

type errorEvent struct {
	event
	ErrorType string `json:"error_type"`
	// Critical should be set to true if the given error prevents DNS configuration
	Critical bool `json:"cricital"`
}

func newErrorEvent(eventType eventType,
	messageNamespace string,
	managementService dnsManagementService,
	errorType errorType,
	critical bool) errorEvent {
	return errorEvent{
		event:     newEvent(eventType, messageNamespace, managementService),
		ErrorType: errorType.String(),
		Critical:  critical,
	}
}

func (e errorEvent) toContextPaths() []events.ContextValue {
	contextPaths := []events.ContextValue{
		{
			Path:  debuggerEventBaseKey + "." + debuggerEventErrorTypeKey,
			Value: e.ErrorType,
		},
		{
			Path:  debuggerEventBaseKey + "." + debuggerEventCriticalKey,
			Value: e.Critical,
		},
	}
	contextPaths = append(contextPaths, e.event.toContextPaths()...)
	return contextPaths
}

func (e errorEvent) toDebuggerEvent() *events.DebuggerEvent {
	jsonData, err := json.Marshal(e)
	if err != nil {
		log.Println(internal.DebugPrefix,
			dnsPrefix,
			"failed to serialize error event json for resovl.conf overwrite:", err)
		jsonData = []byte("{}")
	}

	debuggerEvent := events.NewDebuggerEvent(string(jsonData)).
		WithKeyBasedContextPaths(e.toContextPaths()...).
		WithGlobalContextPaths(globalPaths...)

	return debuggerEvent
}

type eventType int

const (
	resolvConfOverwrittenEventType eventType = iota
	dnsConfiguredEventType
	dnsConfigurationErrorEventType
)

func (e eventType) String() string {
	switch e {
	case resolvConfOverwrittenEventType:
		return "resolvconf_overwritten"
	case dnsConfiguredEventType:
		return "dns_configured"
	case dnsConfigurationErrorEventType:
		return "dns_configuration_error"
	default:
		return fmt.Sprintf("%d", e)
	}
}

type dnsManagementService int

const (
	systemdResolvedService dnsManagementService = iota
	unmanagedService
	unknownService
)

func (e dnsManagementService) String() string {
	switch e {
	case systemdResolvedService:
		return "systemd-resolved"
	case unmanagedService:
		return "unmanaged"
	case unknownService:
		return "unknown"
	default:
		return fmt.Sprintf("%d", e)
	}
}

type errorType int

const (
	setFailedErrorType errorType = iota
	detectionFailedErrorType
)

func (e errorType) String() string {
	switch e {
	case setFailedErrorType:
		return "set_failed"
	case detectionFailedErrorType:
		return "failed_to_detect_management_service"
	default:
		return fmt.Sprintf("%d", e)
	}
}

type analytics interface {
	setManagementService(dnsManagementService)
	emitResolvConfOverwrittenEvent()
	emitDNSConfiguredEvent()
	emitDNSConfigurationErrorEvent(errorType errorType, critical bool)
}

type dnsAnalytics struct {
	mu                sync.Mutex
	debugPublisher    events.Publisher[events.DebuggerEvent]
	managementService dnsManagementService
}

func newDNSAnalytics(publisher events.Publisher[events.DebuggerEvent]) *dnsAnalytics {
	return &dnsAnalytics{
		debugPublisher:    publisher,
		managementService: unknownService,
	}
}

// setManagementService sets management service to be used in the context of DNS related debugger events
func (d *dnsAnalytics) setManagementService(managementService dnsManagementService) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.managementService = managementService
}

func (d *dnsAnalytics) emitResolvConfOverwrittenEvent() {
	d.mu.Lock()
	defer d.mu.Unlock()

	debuggerEvent := newEvent(resolvConfOverwrittenEventType,
		internal.DebugEventMessageNamespace,
		d.managementService).toDebuggerEvent()

	log.Printf("%s%s publishing event: %+v", internal.DebugPrefix, dnsPrefix, debuggerEvent)

	d.debugPublisher.Publish(*debuggerEvent)
}

func (d *dnsAnalytics) emitDNSConfiguredEvent() {
	d.mu.Lock()
	defer d.mu.Unlock()

	debuggerEvent := newEvent(dnsConfiguredEventType,
		internal.DebugEventMessageNamespace,
		d.managementService).toDebuggerEvent()

	log.Printf("%s%s publishing event: %+v", internal.DebugPrefix, dnsPrefix, debuggerEvent)

	d.debugPublisher.Publish(*debuggerEvent)
}

func (d *dnsAnalytics) emitDNSConfigurationErrorEvent(errorType errorType, critical bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	debuggerEvent := newErrorEvent(dnsConfigurationErrorEventType,
		internal.DebugEventMessageNamespace,
		d.managementService,
		errorType,
		critical).toDebuggerEvent()

	log.Printf("%s%s publishing event: %+v", internal.DebugPrefix, dnsPrefix, debuggerEvent)

	d.debugPublisher.Publish(*debuggerEvent)
}
