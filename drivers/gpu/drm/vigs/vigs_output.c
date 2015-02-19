#include "vigs_output.h"
#include "vigs_device.h"
#include "drm_crtc_helper.h"
#include <linux/init.h>

#define DPI_DEF_VALUE 3160
#define DPI_MIN_VALUE 1000
#define DPI_MAX_VALUE 4800

#ifndef MODULE
static int vigs_atoi(const char *str)
{
    int val = 0;

    for (;; ++str) {
        switch (*str) {
        case '0' ... '9':
            val = (10 * val) + (*str - '0');
            break;
        default:
            return val;
        }
    }
}
#endif

struct vigs_output
{
    /*
     * 'connector' is the owner of the 'vigs_output', i.e.
     * when 'connector' is destroyed whole structure is destroyed.
     */
    struct drm_connector connector;
    struct drm_encoder encoder;
};

static inline struct vigs_output *connector_to_vigs_output(struct drm_connector *connector)
{
    return container_of(connector, struct vigs_output, connector);
}

static inline struct vigs_output *encoder_to_vigs_output(struct drm_encoder *encoder)
{
    return container_of(encoder, struct vigs_output, encoder);
}

static void vigs_connector_save(struct drm_connector *connector)
{
    DRM_DEBUG_KMS("enter\n");
}

static void vigs_connector_restore(struct drm_connector *connector)
{
    DRM_DEBUG_KMS("enter\n");
}

static enum drm_connector_status vigs_connector_detect(
    struct drm_connector *connector,
    bool force)
{
    DRM_DEBUG_KMS("enter: force = %d\n", force);

    return connector_status_connected;
}

static int vigs_connector_set_property(struct drm_connector *connector,
                                       struct drm_property *property,
                                       uint64_t value)
{
    DRM_DEBUG_KMS("enter: %s = %llu\n", property->name, value);

    return 0;
}

static void vigs_connector_destroy(struct drm_connector *connector)
{
    struct vigs_output *vigs_output = connector_to_vigs_output(connector);

    DRM_DEBUG_KMS("enter\n");

    drm_sysfs_connector_remove(connector);
    drm_connector_cleanup(connector);

    kfree(vigs_output);
}

static int vigs_connector_get_modes(struct drm_connector *connector)
{
    struct vigs_output *vigs_output = connector_to_vigs_output(connector);
    struct drm_device *drm_dev = vigs_output->connector.dev;
    char *option = NULL;

    DRM_DEBUG_KMS("enter\n");

    if (fb_get_options(drm_get_connector_name(connector), &option) == 0) {
        struct drm_cmdline_mode cmdline_mode;

        if (drm_mode_parse_command_line_for_connector(option,
                                                      connector,
                                                      &cmdline_mode)) {
            struct drm_display_mode *preferred_mode =
                drm_mode_create_from_cmdline_mode(drm_dev,
                                                  &cmdline_mode);
            preferred_mode->type = DRM_MODE_TYPE_PREFERRED | DRM_MODE_TYPE_DRIVER;
            drm_mode_probed_add(connector, preferred_mode);
            return 1;
        }
    }

    return 0;
}

static int vigs_connector_mode_valid(struct drm_connector *connector,
                                     struct drm_display_mode *mode)
{
    DRM_DEBUG_KMS("enter\n");

    return MODE_OK;
}

struct drm_encoder *vigs_connector_best_encoder(struct drm_connector *connector)
{
    struct vigs_output *vigs_output = connector_to_vigs_output(connector);

    DRM_DEBUG_KMS("enter\n");

    return &vigs_output->encoder;
}

static void vigs_encoder_destroy(struct drm_encoder *encoder)
{
    DRM_DEBUG_KMS("enter\n");

    drm_encoder_cleanup(encoder);
}

static void vigs_encoder_dpms(struct drm_encoder *encoder, int mode)
{
    DRM_DEBUG_KMS("enter: mode = %d\n", mode);
}

static bool vigs_encoder_mode_fixup(struct drm_encoder *encoder,
                                    const struct drm_display_mode *mode,
                                    struct drm_display_mode *adjusted_mode)
{
    DRM_DEBUG_KMS("enter\n");

    return true;
}

static void vigs_encoder_prepare(struct drm_encoder *encoder)
{
    DRM_DEBUG_KMS("enter\n");
}

static void vigs_encoder_mode_set(struct drm_encoder *encoder,
                                  struct drm_display_mode *mode,
                                  struct drm_display_mode *adjusted_mode)
{
    DRM_DEBUG_KMS("enter\n");
}

static void vigs_encoder_commit(struct drm_encoder *encoder)
{
    DRM_DEBUG_KMS("enter\n");
}

static const struct drm_connector_funcs vigs_connector_funcs =
{
    .dpms = drm_helper_connector_dpms,
    .save = vigs_connector_save,
    .restore = vigs_connector_restore,
    .detect = vigs_connector_detect,
    .fill_modes = drm_helper_probe_single_connector_modes,
    .set_property = vigs_connector_set_property,
    .destroy = vigs_connector_destroy,
};

static const struct drm_connector_helper_funcs vigs_connector_helper_funcs =
{
    .get_modes = vigs_connector_get_modes,
    .mode_valid = vigs_connector_mode_valid,
    .best_encoder = vigs_connector_best_encoder,
};

static const struct drm_encoder_funcs vigs_encoder_funcs =
{
    .destroy = vigs_encoder_destroy,
};

static const struct drm_encoder_helper_funcs vigs_encoder_helper_funcs =
{
    .dpms = vigs_encoder_dpms,
    .mode_fixup = vigs_encoder_mode_fixup,
    .prepare = vigs_encoder_prepare,
    .mode_set = vigs_encoder_mode_set,
    .commit = vigs_encoder_commit,
};

int vigs_output_init(struct vigs_device *vigs_dev)
{
    struct vigs_output *vigs_output;
    int ret;

    DRM_DEBUG_KMS("enter\n");

    vigs_output = kzalloc(sizeof(*vigs_output), GFP_KERNEL);

    if (!vigs_output) {
        return -ENOMEM;
    }

    ret = drm_connector_init(vigs_dev->drm_dev,
                             &vigs_output->connector,
                             &vigs_connector_funcs,
                             DRM_MODE_CONNECTOR_LVDS);

    if (ret != 0) {
        kfree(vigs_output);
        return ret;
    }

    ret = drm_encoder_init(vigs_dev->drm_dev,
                           &vigs_output->encoder,
                           &vigs_encoder_funcs,
                           DRM_MODE_ENCODER_LVDS);

    if (ret != 0) {
        /*
         * KMS subsystem will delete 'vigs_output'
         */

        return ret;
    }

    /*
     * We only have a single CRTC.
     */
    vigs_output->encoder.possible_crtcs = (1 << 0);

    ret = drm_mode_connector_attach_encoder(&vigs_output->connector,
                                            &vigs_output->encoder);

    if (ret != 0) {
        return ret;
    }

    drm_encoder_helper_add(&vigs_output->encoder, &vigs_encoder_helper_funcs);

    drm_connector_helper_add(&vigs_output->connector, &vigs_connector_helper_funcs);

    ret = drm_sysfs_connector_add(&vigs_output->connector);

    if (ret != 0) {
        return ret;
    }

    return 0;
}

int vigs_output_get_dpi(void)
{
    int dpi = DPI_DEF_VALUE;
#ifndef MODULE
    char *str;
    char dpi_info[16];

    str = strstr(saved_command_line, "dpi=");

    if (str != NULL) {
        str += 4;
        strncpy(dpi_info, str, 4);
        dpi = vigs_atoi(dpi_info);
        if ((dpi < DPI_MIN_VALUE) || (dpi > DPI_MAX_VALUE)) {
            dpi = DPI_DEF_VALUE;
        }
    }
#endif
    return dpi;
}

int vigs_output_get_phys_width(int dpi, u32 width)
{
    return ((width * 2540 / dpi) + 5) / 10;
}

int vigs_output_get_phys_height(int dpi, u32 height)
{
    return ((height * 2540 / dpi) + 5) / 10;
}
