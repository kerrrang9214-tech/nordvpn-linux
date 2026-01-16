package dns

import (
	"context"
	"testing"
	"time"

	"github.com/NordSecurity/nordvpn-linux/test/category"
	"github.com/fsnotify/fsnotify"
	"gotest.tools/v3/assert"
)

type mockErrorEvent struct {
	errorType errorType
	critical  bool
}

type analyticsMock struct {
	resolvConfEventEmitted bool
	dnsConfiguredEmited    bool
	managementService      dnsManagementService
	emittedErrors          []mockErrorEvent
}

func (a *analyticsMock) setManagementService(managementService dnsManagementService) {
	a.managementService = managementService
}

func (a *analyticsMock) emitResolvConfOverwrittenEvent() {
	a.resolvConfEventEmitted = true
}

func (a *analyticsMock) emitDNSConfiguredEvent() {
	a.dnsConfiguredEmited = true
}

func (a *analyticsMock) emitDNSConfigurationErrorEvent(errorType errorType, critical bool) {
	a.emittedErrors = append(a.emittedErrors, mockErrorEvent{errorType: errorType, critical: critical})
}

func newAnalyticsMock() analyticsMock {
	return analyticsMock{}
}

// checkLoop executes test in an interval untill it returns true or a timeout is reached
func checkLoop(test func() bool, interval time.Duration, timeout time.Duration) bool {
	if test() {
		return true
	}
	resultChan := make(chan bool)
	ctx := context.Background()

	go func() {
		for {
			select {
			case <-time.After(interval):
				if test() {
					resultChan <- true
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-time.After(timeout):
			ctx.Done()
			return false
		case <-resultChan:
			return true
		}
	}
}

func Test_ResolvConfMonitoring(t *testing.T) {
	category.Set(t, category.Unit)

	eventsChan := make(chan fsnotify.Event)
	errorChan := make(chan error)
	getMockWatcherFunc := func() (*fsnotify.Watcher, error) {
		watcher, _ := fsnotify.NewWatcher()
		watcher.Events = eventsChan
		watcher.Errors = errorChan
		return watcher, nil
	}

	analyticsMock := newAnalyticsMock()

	resolvConfMonitor := resolvConfFileWatcherMonitor{
		analytics:      &analyticsMock,
		getWatcherFunc: getMockWatcherFunc,
	}

	resolvConfMonitor.Start()
	eventsChan <- fsnotify.Event{}
	checkResultFunc := func() bool {
		return analyticsMock.resolvConfEventEmitted
	}
	revolvConfEventEmitted := checkLoop(checkResultFunc, 10*time.Millisecond, 1*time.Second)

	assert.Equal(t, true, revolvConfEventEmitted, "Event was not emitted after resolv.conf change was detected.")
}
