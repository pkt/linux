#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/input.h>

#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_input.h>

struct virtio_input {
	struct virtio_device       *vdev;
	struct input_dev           *idev;
	char                       name[64];
	char                       serial[64];
	char                       phys[64];
	struct virtqueue           *evt, *sts;
	struct virtio_input_event  evts[64];
};

static ssize_t serial_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct input_dev *idev = to_input_dev(dev);
	struct virtio_input *vi = input_get_drvdata(idev);
	return sprintf(buf, "%s\n", vi->serial);
}
static DEVICE_ATTR_RO(serial);

static struct attribute *dev_attrs[] = {
	&dev_attr_serial.attr,
	NULL
};

static umode_t dev_attrs_are_visible(struct kobject *kobj,
				     struct attribute *a, int n)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct input_dev *idev = to_input_dev(dev);
	struct virtio_input *vi = input_get_drvdata(idev);

	if (a == &dev_attr_serial.attr && !strlen(vi->serial))
		return 0;

	return a->mode;
}

static struct attribute_group dev_attr_grp = {
	.attrs =	dev_attrs,
	.is_visible =	dev_attrs_are_visible,
};

static const struct attribute_group *dev_attr_groups[] = {
	&dev_attr_grp,
	NULL
};

static void virtinput_queue_evtbuf(struct virtio_input *vi,
				   struct virtio_input_event *evtbuf)
{
	struct scatterlist sg[1];

	sg_init_one(sg, evtbuf, sizeof(*evtbuf));
	virtqueue_add_inbuf(vi->evt, sg, 1, evtbuf, GFP_ATOMIC);
}

static void virtinput_recv_events(struct virtqueue *vq)
{
	struct virtio_input *vi = vq->vdev->priv;
	struct virtio_input_event *event;
	unsigned int len;

	while ((event = virtqueue_get_buf(vi->evt, &len)) != NULL) {
		input_event(vi->idev,
			    le16_to_cpu(event->type),
			    le16_to_cpu(event->code),
			    le32_to_cpu(event->value));
		virtinput_queue_evtbuf(vi, event);
	}
	virtqueue_kick(vq);
}

static int virtinput_send_status(struct virtio_input *vi,
				 u16 type, u16 code, s32 value)
{
	struct virtio_input_event *stsbuf;
	struct scatterlist sg[1];

	stsbuf = kzalloc(sizeof(*stsbuf), GFP_ATOMIC);
	if (!stsbuf)
		return -ENOMEM;

	stsbuf->type  = cpu_to_le16(type);
	stsbuf->code  = cpu_to_le16(code);
	stsbuf->value = cpu_to_le32(value);
	sg_init_one(sg, stsbuf, sizeof(*stsbuf));
	virtqueue_add_outbuf(vi->sts, sg, 1, stsbuf, GFP_ATOMIC);
	virtqueue_kick(vi->sts);
	return 0;
}

static void virtinput_recv_status(struct virtqueue *vq)
{
	struct virtio_input *vi = vq->vdev->priv;
	struct virtio_input_event *stsbuf;
	unsigned int len;

	while ((stsbuf = virtqueue_get_buf(vi->sts, &len)) != NULL)
		kfree(stsbuf);
	virtqueue_kick(vq);
}

static int virtinput_status(struct input_dev *idev, unsigned int type,
			    unsigned int code, int value)
{
	struct virtio_input *vi = input_get_drvdata(idev);

	return virtinput_send_status(vi, type, code, value);
}

static size_t virtinput_cfg_select(struct virtio_input *vi,
				   u8 select, u8 subsel)
{
	u8 size;

	virtio_cwrite(vi->vdev, struct virtio_input_config, select, &select);
	virtio_cwrite(vi->vdev, struct virtio_input_config, subsel, &subsel);
	virtio_cread(vi->vdev, struct virtio_input_config, size, &size);
	return size;
}

static void virtinput_cfg_bits(struct virtio_input *vi, int select, int subsel,
			       unsigned long *bits, unsigned int bitcount)
{
	unsigned int bit;
	size_t bytes;
	u8 cfg = 0;

	bytes = virtinput_cfg_select(vi, select, subsel);
	if (!bytes)
		return;
	if (bitcount > bytes*8)
		bitcount = bytes*8;
	if (select == VIRTIO_INPUT_CFG_EV_BITS)
		set_bit(subsel, vi->idev->evbit);
	for (bit = 0; bit < bitcount; bit++) {
		if ((bit % 8) == 0)
			virtio_cread(vi->vdev, struct virtio_input_config,
				     u.bitmap[bit/8], &cfg);
		if (cfg & (1 << (bit % 8)))
			set_bit(bit, bits);
	}
}

static void virtinput_cfg_abs(struct virtio_input *vi, int abs)
{
	u32 size, mi, ma, fu, fl;

	size = virtinput_cfg_select(vi, VIRTIO_INPUT_CFG_ABS_INFO, abs);
	virtio_cread(vi->vdev, struct virtio_input_config, u.abs.min, &mi);
	virtio_cread(vi->vdev, struct virtio_input_config, u.abs.max, &ma);
	virtio_cread(vi->vdev, struct virtio_input_config, u.abs.fuzz, &fu);
	virtio_cread(vi->vdev, struct virtio_input_config, u.abs.flat, &fl);
	input_set_abs_params(vi->idev, abs,
			     le32_to_cpu(mi), le32_to_cpu(ma),
			     le32_to_cpu(fu), le32_to_cpu(fl));
}

static int virtinput_init_vqs(struct virtio_input *vi)
{
	struct virtqueue *vqs[2];
	vq_callback_t *cbs[] = { virtinput_recv_events,
				 virtinput_recv_status };
	const char *names[] = { "events", "status" };
	int i, err, size;

	err = vi->vdev->config->find_vqs(vi->vdev, 2, vqs, cbs, names);
	if (err)
		return err;
	vi->evt = vqs[0];
	vi->sts = vqs[1];

	size = virtqueue_get_vring_size(vi->evt);
	if (size > ARRAY_SIZE(vi->evts))
		size = ARRAY_SIZE(vi->evts);
	for (i = 0; i < size; i++)
		virtinput_queue_evtbuf(vi, &vi->evts[i]);

	return 0;
}

static int virtinput_probe(struct virtio_device *vdev)
{
	struct virtio_input *vi;
	size_t size;
	int abs, err;

	vi = kzalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi) {
		err = -ENOMEM;
		goto out1;
	}
	vdev->priv = vi;
	vi->vdev = vdev;

	err = virtinput_init_vqs(vi);
	if (err)
		goto out2;

	vi->idev = input_allocate_device();
	if (!vi->idev) {
		err = -ENOMEM;
		goto out3;
	}
	input_set_drvdata(vi->idev, vi);

	size = virtinput_cfg_select(vi, VIRTIO_INPUT_CFG_ID_NAME, 0);
	virtio_cread_bytes(vi->vdev, offsetof(struct virtio_input_config, u),
			   vi->name, min(size, sizeof(vi->name)));
	size = virtinput_cfg_select(vi, VIRTIO_INPUT_CFG_ID_SERIAL, 0);
	virtio_cread_bytes(vi->vdev, offsetof(struct virtio_input_config, u),
			   vi->serial, min(size, sizeof(vi->serial)));
	snprintf(vi->phys, sizeof(vi->phys),
		 "virtio%d/input0", vdev->index);

	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_PROP_BITS, 0,
			   vi->idev->propbit, INPUT_PROP_CNT);
	size = virtinput_cfg_select(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_REP);
	if (size)
		set_bit(EV_REP, vi->idev->evbit);

	vi->idev->name = vi->name;
	vi->idev->phys = vi->phys;
	vi->idev->id.bustype = BUS_VIRTUAL;
	vi->idev->id.vendor  = 0x0001;
	vi->idev->id.product = 0x0001;
	vi->idev->id.version = 0x0100;
	vi->idev->dev.parent = &vdev->dev;
	vi->idev->dev.groups = dev_attr_groups;
	vi->idev->event = virtinput_status;

	/* device -> kernel */
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_KEY,
			   vi->idev->keybit, KEY_CNT);
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_REL,
			   vi->idev->relbit, REL_CNT);
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_ABS,
			   vi->idev->absbit, ABS_CNT);
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_MSC,
			   vi->idev->mscbit, MSC_CNT);
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_SW,
			   vi->idev->swbit,  SW_CNT);

	/* kernel -> device */
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_LED,
			   vi->idev->ledbit, LED_CNT);
	virtinput_cfg_bits(vi, VIRTIO_INPUT_CFG_EV_BITS, EV_SND,
			   vi->idev->sndbit, SND_CNT);

	if (test_bit(EV_ABS, vi->idev->evbit)) {
		for (abs = 0; abs < ABS_CNT; abs++) {
			if (!test_bit(abs, vi->idev->absbit))
				continue;
			virtinput_cfg_abs(vi, abs);
		}
	}

	err = input_register_device(vi->idev);
	if (err)
		goto out4;

	return 0;

out4:
	input_free_device(vi->idev);
out3:
	vdev->config->del_vqs(vdev);
out2:
	kfree(vi);
out1:
	return err;
}

static void virtinput_remove(struct virtio_device *vdev)
{
	struct virtio_input *vi = vdev->priv;

	input_unregister_device(vi->idev);
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
	kfree(vi);
}

static unsigned int features[] = {
};
static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_INPUT, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_input_driver = {
	.driver.name         = KBUILD_MODNAME,
	.driver.owner        = THIS_MODULE,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtinput_probe,
	.remove              = virtinput_remove,
};

module_virtio_driver(virtio_input_driver);
MODULE_DEVICE_TABLE(virtio, id_table);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtio input device driver");
MODULE_AUTHOR("Gerd Hoffmann <kraxel@redhat.com>");
