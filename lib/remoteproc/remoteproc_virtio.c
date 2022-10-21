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

#ifdef NK_SOCKETS

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

#else /*NK_SOCKETS*/
static void rproc_virtio_virtqueue_notify(struct virtqueue *vq)
{
	struct remoteproc_virtio *rpvdev;
	struct virtio_vring_info *vring_info;
	struct virtio_device *vdev;
	unsigned int vq_id = vq->vq_queue_index;

	vdev = vq->vq_dev;
	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	metal_assert(vq_id < vdev->vrings_num);
	vring_info = &vdev->vrings_info[vq_id];
	rpvdev->notify(rpvdev->priv, vring_info->notifyid);
}
#endif /*NK_SOCKETS*/

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
#ifdef NK_SOCKETS
	(void)vdev;
	(void)offset;
	(void)dst;
	(void)length;
	printf("CHECK :( entering rproc_virtio_read_config");
#else /*NK_SOCKETS*/
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;
	char *config;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	config = (char *)(&vdev_rsc->vring[vdev->vrings_num]);
	io = rpvdev->vdev_rsc_io;

	if (offset + length <= vdev_rsc->config_len)
		metal_io_block_read(io,
				metal_io_virt_to_offset(io, config + offset),
				dst, length);
#endif /*NK_SOCKETS*/
}

#ifndef VIRTIO_DEVICE_ONLY
static void rproc_virtio_write_config(struct virtio_device *vdev,
				      uint32_t offset, void *src, int length)
{
#ifdef NK_SOCKETS
	(void)vdev;
	(void)offset;
	(void)src;
	(void)length;
	printf("CHECK :( entering rproc_virtio_write_config");
#else /*NK_SOCKETS*/
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *io;
	char *config;

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	config = (char *)(&vdev_rsc->vring[vdev->vrings_num]);
	io = rpvdev->vdev_rsc_io;

	if (offset + length <= vdev_rsc->config_len) {
		metal_io_block_write(io,
				metal_io_virt_to_offset(io, config + offset),
				src, length);
		rpvdev->notify(rpvdev->priv, vdev->notifyid);
	}
#endif /*NK_SOCKETS*/
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
#ifdef NK_SOCKETS
	.notify = vdev_notify,
#else
	.notify = rproc_virtio_virtqueue_notify,
#endif /*NK_SOCKETS*/

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
#ifdef NK_SOCKETS
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

#else /*NK_SOCKETS*/
	struct remoteproc_virtio *rpvdev;
	struct virtio_vring_info *vrings_info;
	struct fw_rsc_vdev *vdev_rsc = rsc;
	struct virtio_device *vdev;
	unsigned int num_vrings = vdev_rsc->num_of_vrings;
	unsigned int i;

	rpvdev = metal_allocate_memory(sizeof(*rpvdev));
	if (!rpvdev)
		return NULL;
	vrings_info = metal_allocate_memory(sizeof(*vrings_info) * num_vrings);
	if (!vrings_info)
		goto err0;
	memset(rpvdev, 0, sizeof(*rpvdev));
	memset(vrings_info, 0, sizeof(*vrings_info));
	vdev = &rpvdev->vdev;

	for (i = 0; i < num_vrings; i++) {
		struct virtqueue *vq;
#ifndef VIRTIO_DEVICE_ONLY
		struct fw_rsc_vdev_vring *vring_rsc;
#endif
		unsigned int num_extra_desc = 0;

#ifndef VIRTIO_DEVICE_ONLY
		vring_rsc = &vdev_rsc->vring[i];
		if (role == VIRTIO_DEV_DRIVER) {
			num_extra_desc = vring_rsc->num;
		}
#endif
		vq = virtqueue_allocate(num_extra_desc);
		if (!vq)
			goto err1;
		vrings_info[i].vq = vq;
	}

	rpvdev->notify = notify;
	rpvdev->priv = priv;
	vdev->vrings_info = vrings_info;
	/* Assuming the shared memory has been mapped and registered if
	 * necessary
	 */
	rpvdev->vdev_rsc = vdev_rsc;
	rpvdev->vdev_rsc_io = rsc_io;

	vdev->notifyid = notifyid;
	vdev->role = role;
	vdev->reset_cb = rst_cb;
	vdev->vrings_num = num_vrings;
	vdev->func = &remoteproc_virtio_dispatch_funcs;

#ifndef VIRTIO_DEVICE_ONLY
	if (role == VIRTIO_DEV_DRIVER) {
		uint32_t dfeatures = rproc_virtio_get_dfeatures(vdev);
		/* Assume the virtio driver support all remote features */
		rproc_virtio_negotiate_features(vdev, dfeatures);
	}
#endif

	return &rpvdev->vdev;

err1:
	for (i = 0; i < num_vrings; i++) {
		if (vrings_info[i].vq)
			metal_free_memory(vrings_info[i].vq);
	}
	metal_free_memory(vrings_info);
err0:
	metal_free_memory(rpvdev);
	return NULL;
#endif /*NK_SOCKETS*/
}

void rproc_virtio_remove_vdev(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
#ifndef NK_SOCKETS
	unsigned int i;
#endif /*NK_SOCKETS*/

	if (!vdev)
		return;
	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
#ifdef NK_SOCKETS
	close(vdev->fd);
#else /*NK_SOCKETS*/
	for (i = 0; i < vdev->vrings_num; i++) {
		struct virtqueue *vq;

		vq = vdev->vrings_info[i].vq;
		if (vq)
			metal_free_memory(vq);
	}
	if (vdev->vrings_info)
		metal_free_memory(vdev->vrings_info);
#endif /*NK_SOCKETS*/
	metal_free_memory(rpvdev);
}

#ifndef NK_SOCKETS
int rproc_virtio_init_vring(struct virtio_device *vdev, unsigned int index,
			    unsigned int notifyid, void *va,
			    struct metal_io_region *io,
			    unsigned int num_descs, unsigned int align)
{
	struct virtio_vring_info *vring_info;
	unsigned int num_vrings;

	num_vrings = vdev->vrings_num;
	if ((index >= num_vrings) || (num_descs > RPROC_MAX_VRING_DESC))
		return -RPROC_EINVAL;
	vring_info = &vdev->vrings_info[index];
	vring_info->io = io;
	vring_info->notifyid = notifyid;
	vring_info->info.vaddr = va;
	vring_info->info.num_descs = num_descs;
	vring_info->info.align = align;

	return 0;
}
#endif /*NK_SOCKETS*/

int rproc_virtio_notified(struct virtio_device *vdev, uint32_t notifyid)
{
#ifndef NK_SOCKETS
	unsigned int num_vrings, i;
	struct virtio_vring_info *vring_info;
	struct virtqueue *vq;
#endif /*NK_SOCKETS*/

	if (!vdev)
		return -RPROC_EINVAL;
	/* We do nothing for vdev notification in this implementation */
	if (vdev->notifyid == notifyid)
		return 0;
#ifdef NK_SOCKETS
	vdev->rx_callback(vdev);
#else /*NK_SOCKETS*/
	num_vrings = vdev->vrings_num;
	for (i = 0; i < num_vrings; i++) {
		vring_info = &vdev->vrings_info[i];
		if (vring_info->notifyid == notifyid ||
		    notifyid == RSC_NOTIFY_ID_ANY) {
			vq = vring_info->vq;
			virtqueue_notification(vq);
		}
	}
#endif /*NK_SOCKETS*/
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
