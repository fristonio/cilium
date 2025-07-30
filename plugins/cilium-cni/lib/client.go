// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/go-openapi/runtime"
)

const (
	// The timeout for connecting and obtaining the lock.
	// The default of 30 seconds is too long; kubelet will time us out before then.
	timeoutSeconds = 10

	// The maximum number of queued deletions allowed, to protect against kubelet insanity.
	maxDeletionFiles = 256
)

var (
	errServiceUnavailable = errors.New("cilium api not available")
)

type CiliumCniClient interface {
	IsAgentHealthy() (bool, error)
	GetAgentConfig() (*models.DaemonConfigurationStatus, error)

	CreateEndpoint(ep *models.EndpointChangeRequest) (*models.Endpoint, error)
	GetEndpointHealth(id string) (*models.EndpointHealth, error)
	DeleteEndpoints(req *models.EndpointBatchDeleteRequest) error

	AllocateIP(podName, ipamPoolName string, expiration bool) (*models.IPAMResponse, func(context.Context), error)
	ReleaseIP(ip, pool string) error
}

type ciliumClient struct {
	logger *slog.Logger
	client *client.Client
}

func NewCiliumCniClient(logger *slog.Logger) CiliumCniClient {
	return &ciliumClient{
		logger: logger,
		client: nil,
	}
}

func newClientWithTimeout(timeout time.Duration) (*client.Client, error) {
	c, err := client.NewDefaultClientWithTimeout(timeout)
	if err != nil {
		// Wrap in an identifiable error for internal use.
		return nil, fmt.Errorf("%w: %w", errServiceUnavailable, err)
	}

	return c, nil
}

func NewDefaultCiliumCniClient(logger *slog.Logger) (CiliumCniClient, error) {
	c, err := newClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		return nil, err
	}

	return &ciliumClient{
		logger: logger,
		client: c,
	}, nil
}

func (cli *ciliumClient) getOrNewClient() (*client.Client, error) {
	if cli.client != nil {
		return cli.client, nil
	}

	return newClientWithTimeout(timeoutSeconds * time.Second)
}

func (cli *ciliumClient) IsAgentHealthy() (bool, error) {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return false, err
	}

	if _, err := cc.Daemon.GetHealthz(nil); err != nil {
		return false, err
	}

	return true, nil
}

func (cli *ciliumClient) GetAgentConfig() (*models.DaemonConfigurationStatus, error) {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return nil, err
	}

	configResult, err := cc.ConfigGet()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve configuration from Cilium agent: %w", err)
	}

	if configResult == nil || configResult.Status == nil {
		return nil, errors.New("received empty configuration object from Cilium agent")
	}

	return configResult.Status, nil
}

func (cli *ciliumClient) CreateEndpoint(ep *models.EndpointChangeRequest) (*models.Endpoint, error) {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return nil, err
	}

	return cc.EndpointCreate(ep)
}

func (cli *ciliumClient) GetEndpointHealth(id string) (*models.EndpointHealth, error) {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return nil, err
	}

	return cc.EndpointHealthGet(id)
}

func (cli *ciliumClient) DeleteEndpoints(req *models.EndpointBatchDeleteRequest) error {
	err := cli.deleteEndpointsBatch(req)

	// If the Endpoint Deletion request to cilium-agent failed, fallback to
	// queuing the deletion.
	if err != nil && errors.Is(err, errServiceUnavailable) {
		cli.logger.Warn(
			"Failed to delete Endpoints batch",
			logfields.Request, req,
			logfields.Error, err,
		)

		lf, err := cli.tryLockDeletionQueue()
		if err != nil {
			return fmt.Errorf("failed to acquire deletion queue lock: %w", err)
		}
		defer lf.Unlock()

		// Retry Endpoints Delete request after acquiring the lock, in case
		// its ready now.
		err = cli.deleteEndpointsBatch(req)
		// Only enqueue the Deletion request if the failure is API server related, so cilium-agent
		// can retry when DeletionQueue is replayed.
		if err != nil && errors.Is(err, errServiceUnavailable) {
			return cli.enqueueDeletionRequestLocked(req)
		}
	}

	return err
}

func (cli *ciliumClient) AllocateIP(podName, ipamPoolName string, expiration bool) (*models.IPAMResponse, func(context.Context), error) {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return nil, nil, err
	}

	ipam, err := cc.IPAMAllocate("", podName, ipamPoolName, expiration)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, errors.New("invalid IPAM response, missing addressing")
	}

	releaseFunc := func(context.Context) {
		if ipam.Address != nil {
			cli.ReleaseIP(ipam.Address.IPV4, ipam.Address.IPV4PoolName)
			cli.ReleaseIP(ipam.Address.IPV6, ipam.Address.IPV6PoolName)
		}
	}

	cli.logger.Debug("IP Address allocated",
		logfields.Pod, podName,
		logfields.PoolName, ipamPoolName,
		logfields.Address, ipam.Address)
	return ipam, releaseFunc, nil
}

func (cli *ciliumClient) ReleaseIP(ip, pool string) error {
	if ip != "" {
		cc, err := cli.getOrNewClient()
		if err != nil {
			return err
		}

		if err := cc.IPAMReleaseIP(ip, pool); err != nil {
			cli.logger.Warn(
				"Unable to release IP",
				logfields.Error, err,
				logfields.IPAddr, ip,
				logfields.PoolName, pool,
			)
		}
	}

	return nil
}

func (cli *ciliumClient) deleteEndpointsBatch(req *models.EndpointBatchDeleteRequest) error {
	cc, err := cli.getOrNewClient()
	if err != nil {
		return err
	}

	err = cc.EndpointDeleteMany(req)
	if err != nil {
		status, ok := err.(runtime.ClientResponseStatus)
		if !ok || !status.IsCode(http.StatusServiceUnavailable) {
			// Propagate unhandled server side Endpoint delete errors.
			return err
		}

		return errServiceUnavailable
	}

	return nil
}

func (cli *ciliumClient) tryLockDeletionQueue() (*lockfile.Lockfile, error) {
	cli.logger.Debug(
		"Attempting to acquire deletion queue lock",
		logfields.Path, defaults.DeleteQueueLockfile,
	)
	startTime := time.Now()

	// Ensure deletion queue directory exists, obtain shared lock
	err := os.MkdirAll(defaults.DeleteQueueDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create deletion queue directory %s: %w", defaults.DeleteQueueDir, err)
	}

	lf, err := lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile %s: %w", defaults.DeleteQueueLockfile, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutSeconds*time.Second)
	defer cancel()

	err = lf.Lock(ctx, false) // get the shared lock
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	cli.logger.Debug("Deletion Queue lock acquired",
		logfields.Path, defaults.DeleteQueueLockfile,
		logfields.Duration, time.Since(startTime))
	return lf, nil
}

// enqueueDeletionRequestLocked enqueues the encoded endpoint deletion request into the
// endpoint deletion queue. Requires the caller to hold the deletion queue lock.
func (cli *ciliumClient) enqueueDeletionRequestLocked(req *models.EndpointBatchDeleteRequest) error {
	cli.logger.Info(
		"Queueing endpoint batch deletion request",
		logfields.Request, req,
	)

	requestContents, err := req.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal endpoint delete request: %w", err)
	}

	// sanity check: if there are too many queued deletes, just return error
	// back up to the kubelet. If we get here, it's either because something
	// has gone wrong with the kubelet, or the agent has been down for a very
	// long time. To guard against long agent startup times (when it empties the
	// queue), limit us to 256 queued deletions. If this does, indeed, overflow,
	// then the kubelet will get the failure and eventually retry deletion.
	files, err := os.ReadDir(defaults.DeleteQueueDir)
	if err != nil {
		cli.logger.Error(
			"Failed to list deletion queue directory",
			logfields.Error, err,
			logfields.Path, defaults.DeleteQueueDir,
		)
		return err
	}
	if len(files) > maxDeletionFiles {
		return fmt.Errorf("deletion queue directory %s has too many entries; aborting", defaults.DeleteQueueDir)
	}

	// hash endpoint id for a random filename
	h := sha256.New()
	h.Write(requestContents)
	filename := fmt.Sprintf("%x.delete", h.Sum(nil))
	path := filepath.Join(defaults.DeleteQueueDir, filename)

	err = os.WriteFile(path, requestContents, 0644)
	if err != nil {
		cli.logger.Error(
			"Failed to write deletion file",
			logfields.Error, err,
			logfields.Path, path,
		)
		return fmt.Errorf("failed to write deletion file %s: %w", path, err)
	}
	cli.logger.Info("Wrote queued deletion file", logfields.Path, path)
	return nil
}
