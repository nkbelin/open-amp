/*
 * Remoteproc Virtio Framework Implementation
 *
 * Copyright(c) 2018 Xilinx Ltd.
 * Copyright(c) 2011 Texas Instruments, Inc.
 * Copyright(c) 2011 Google, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <openamp/remoteproc.h>
#include <openamp/remoteproc_virtio.h>
#include <openamp/virtqueue.h>
#include <metal/cpu.h>
#include <metal/utilities.h>
#include <metal/alloc.h>

/* Big copy paste of the functions found in the linuc platform info */

#include <sys/socket.h>
#include <sys/un.h>
#define UNIX_PREFIX "unix:"
#define UNIXS_PREFIX "unixs:"


static int sk_unix_client(const char *descr)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, descr + strlen(UNIX_PREFIX),
		sizeof addr.sun_path);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) >= 0) {
		printf("connected to %s\r\n", descr + strlen(UNIX_PREFIX));
		return fd;
	}

	close(fd);
	return -1;
}

static int sk_unix_server(const char *descr)
{
	struct sockaddr_un addr;
	int fd, nfd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, descr + strlen(UNIXS_PREFIX),
		sizeof addr.sun_path);
	unlink(addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		goto fail;
	}

	listen(fd, 5);
	printf("Waiting for connection on %s\r\n", addr.sun_path);
	nfd = accept(fd, NULL, NULL);
	close(fd);
	return nfd;
fail:
	close(fd);
	return -1;
}

static inline int is_sk_unix_server(const char *descr)
{
	if (memcmp(UNIXS_PREFIX, descr, strlen(UNIXS_PREFIX)))
		return 0;
	else
		return 1;
}

static int event_open(const char *descr)
{
	int fd = -1;
	int i;

	if (descr == NULL) {
		return fd;
	}

	if (!is_sk_unix_server(descr)) {
		/* UNIX client.  Retry to connect a few times to give the peer
		 *  a chance to setup.  */
		for (i = 0; i < 100 && fd == -1; i++) {
			fd = sk_unix_client(descr);
			if (fd == -1)
				usleep(i * 10 * 1000);
		}
	} else {
		/* UNIX server. */
		fd = sk_unix_server(descr);
	}
	printf("Open IPI: %s\r\n", descr);
	return fd;
}


int vdev_notify(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	return rpvdev->notify(rpvdev->priv, vdev->notifyid);
}

static unsigned char rproc_virtio_get_status(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;
	char status;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	io = rpvdev->vdev_rsc_io;
	status = metal_io_read8(io,
				metal_io_virt_to_offset(io, &vdev_rsc->status));
	return status;
}

#ifndef VIRTIO_DEVICE_ONLY
static void rproc_virtio_set_status(struct virtio_device *vdev,
				    unsigned char status)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	io = rpvdev->vdev_rsc_io;
	metal_io_write8(io,
			metal_io_virt_to_offset(io, &vdev_rsc->status),
			status);
	rpvdev->notify(rpvdev->priv, vdev->notifyid);
}
#endif

static uint32_t rproc_virtio_get_dfeatures(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;
	uint32_t features;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	io = rpvdev->vdev_rsc_io;
	features = metal_io_read32(io,
			metal_io_virt_to_offset(io, &vdev_rsc->dfeatures));

	return features;
}

static uint32_t rproc_virtio_get_features(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;
	uint32_t gfeatures;
	uint32_t dfeatures;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	io = rpvdev->vdev_rsc_io;
	gfeatures = metal_io_read32(io,
			metal_io_virt_to_offset(io, &vdev_rsc->gfeatures));
	dfeatures = rproc_virtio_get_dfeatures(vdev);

	return dfeatures & gfeatures;
}

#ifndef VIRTIO_DEVICE_ONLY
static void rproc_virtio_set_features(struct virtio_device *vdev,
				      uint32_t features)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	io = rpvdev->vdev_rsc_io;
	metal_io_write32(io,
			 metal_io_virt_to_offset(io, &vdev_rsc->gfeatures),
			 features);
	rpvdev->notify(rpvdev->priv, vdev->notifyid);
}

static uint32_t rproc_virtio_negotiate_features(struct virtio_device *vdev,
						uint32_t features)
{
	uint32_t dfeatures = rproc_virtio_get_dfeatures(vdev);

	rproc_virtio_set_features(vdev, dfeatures & features);

	return 0;
}
#endif

static void rproc_virtio_read_config(struct virtio_device *vdev,
				     uint32_t offset, void *dst, int length)
{
	printf("CHECK :( entering rproc_virtio_read_config");
}

#ifndef VIRTIO_DEVICE_ONLY
static void rproc_virtio_write_config(struct virtio_device *vdev,
				      uint32_t offset, void *src, int length)
{
	printf("CHECK :( entering rproc_virtio_write_config");
}

static void rproc_virtio_reset_device(struct virtio_device *vdev)
{
	if (vdev->role == VIRTIO_DEV_DRIVER)
		rproc_virtio_set_status(vdev,
					VIRTIO_CONFIG_STATUS_NEEDS_RESET);
}
#endif

static const struct virtio_dispatch remoteproc_virtio_dispatch_funcs = {
	.get_status = rproc_virtio_get_status,
	.get_features = rproc_virtio_get_features,
	.read_config = rproc_virtio_read_config,
	.notify = vdev_notify,
#ifndef VIRTIO_DEVICE_ONLY
	/*
	 * We suppose here that the vdev is in a shared memory so that can
	 * be access only by one core: the host. In this case salve core has
	 * only read access right.
	 */
	.set_status = rproc_virtio_set_status,
	.set_features = rproc_virtio_set_features,
	.negotiate_features = rproc_virtio_negotiate_features,
	.write_config = rproc_virtio_write_config,
	.reset_device = rproc_virtio_reset_device,
#endif
};

struct virtio_device *
rproc_virtio_create_vdev(unsigned int role, unsigned int notifyid,
			 void *rsc, struct metal_io_region *rsc_io,
			 void *priv,
			 rpvdev_notify_func notify,
			 virtio_dev_reset_cb rst_cb)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc = rsc;
	struct virtio_device *vdev;

	rpvdev = metal_allocate_memory(sizeof(*rpvdev));
	if (!rpvdev)
		return NULL;
	memset(rpvdev, 0, sizeof(*rpvdev));
	vdev = &rpvdev->vdev;

	rpvdev->notify = notify;
	rpvdev->priv = priv;


	rpvdev->vdev_rsc = vdev_rsc;
	rpvdev->vdev_rsc_io = rsc_io;

	vdev->notifyid = notifyid;
	vdev->role = role;
	vdev->reset_cb = rst_cb;
	vdev->func = &remoteproc_virtio_dispatch_funcs;
	const char *host_descr = "unixs:/tmp/openamp.nk.0";
	const char *remote_descr = "unix:/tmp/openamp.nk.0";
	if (role == VIRTIO_DEV_DEVICE) {
		vdev->fd = event_open(remote_descr);
	}
	if (role == VIRTIO_DEV_DRIVER) {
		vdev->fd = event_open(host_descr);
	}

#ifndef VIRTIO_DEVICE_ONLY
	if (role == VIRTIO_DEV_DRIVER) {
		uint32_t dfeatures = rproc_virtio_get_dfeatures(vdev);
		/* Assume the virtio driver support all remote features */
		rproc_virtio_negotiate_features(vdev, dfeatures);
	}
#endif

	return &rpvdev->vdev;
}

void rproc_virtio_remove_vdev(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	unsigned int i;

	if (!vdev)
		return;
	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	close(vdev->fd);
	metal_free_memory(rpvdev);
}


int rproc_virtio_notified(struct virtio_device *vdev, uint32_t notifyid)
{

	if (!vdev)
		return -RPROC_EINVAL;
	/* We do nothing for vdev notification in this implementation */
	if (vdev->notifyid == notifyid)
		return 0;

	rpmsg_virtio_rx_callback(vdev);
	return 0;
}

void rproc_virtio_wait_remote_ready(struct virtio_device *vdev)
{
	uint8_t status;

#ifndef VIRTIO_DEVICE_ONLY
	/*
	 * No status available for remote. As virtio driver has not to wait
	 * remote action, we can return. Behavior should be updated
	 * in future if a remote status is added.
	 */
	if (vdev->role == VIRTIO_DEV_DRIVER)
		return;
#endif
	while (1) {
		status = rproc_virtio_get_status(vdev);
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			return;
		metal_cpu_yield();
	}
}
