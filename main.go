/****************************************
 *                                      *
 *  RedTeam Pentesting GmbH             *
 *  kontakt@redteam-pentesting.de       *
 *  https://www.redteam-pentesting.de/  *
 *                                      *
 ****************************************/
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	config, logger, err := configFromCLI()
	if err != nil {
		logger.Errorf("Error: " + err.Error())
		logger.Flush()

		if errors.As(err, &interfaceError{}) {
			logger.Errorf("Try specifying one of the following interfaces:")
			logger.Flush()

			_ = listInterfaces(stdErr, config.NoColor)
		}

		logger.Close()

		os.Exit(1)
	}

	runListeners(config, logger)

	logger.Close()
}

func runListeners(config Config, logger *Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
	defer cancel()

	if config.StopAfter > 0 {
		ctx, cancel = context.WithTimeout(ctx, config.StopAfter)
		defer cancel()
	}

	wg := newServiceWaitGroup(ctx)

	if !config.NoNetBIOS && !config.NoLocalNameResolution {
		wg.Run(RunNetBIOSResponder, logger.WithPrefix("NetBIOS"), config)
	}

	if !config.NoLLMNR && !config.NoLocalNameResolution {
		wg.Run(RunLLMNRResponder, logger.WithPrefix("LLMNR"), config)
	}

	if !config.NoMDNS && !config.NoLocalNameResolution {
		wg.Run(RunMDNSResponder, logger.WithPrefix("mDNS"), config)
	}

	if !config.NoDHCPv6DNSTakeover && !config.NoDNS {
		wg.Run(RunDNSResponder, logger.WithPrefix("DNS"), config)
	}

	if !config.NoDHCPv6DNSTakeover && !config.NoDHCPv6 {
		wg.Run(RunDHCPv6Server, logger.WithPrefix("DHCPv6"), config)
	}

	if !config.NoRA && !config.NoDHCPv6DNSTakeover && !config.NoDHCPv6 {
		wg.Run(SendPeriodicRouterAdvertisements, logger.WithPrefix("RA"), config)
	}

	wg.Wait()
}

type serviceFunc func(context.Context, *Logger, Config) error

type serviceWaitGroup struct {
	ctx context.Context // nolint:containedctx
	sync.WaitGroup
}

func newServiceWaitGroup(ctx context.Context) *serviceWaitGroup {
	return &serviceWaitGroup{ctx: ctx}
}

func (wg *serviceWaitGroup) Run(service serviceFunc, logger *Logger, config Config) {
	wg.WaitGroup.Add(1)

	go func() {
		err := service(wg.ctx, logger, config)
		if err != nil {
			logger.Errorf(escapeFormatString(err.Error()))
		} else if wg.ctx.Err() != nil {
			logger.Debugf("shutdown")
		}

		wg.WaitGroup.Done()
	}()
}
