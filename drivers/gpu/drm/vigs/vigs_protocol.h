#ifndef _VIGS_PROTOCOL_H_
#define _VIGS_PROTOCOL_H_

/*
 * VIGS protocol is a multiple request-no response protocol.
 */

/*
 * Bump this whenever protocol changes.
 */
#define VIGS_PROTOCOL_VERSION 20

#define VIGS_MAX_PLANES 2

typedef signed char vigsp_s8;
typedef signed short vigsp_s16;
typedef signed int vigsp_s32;
typedef signed long long vigsp_s64;
typedef unsigned char vigsp_u8;
typedef unsigned short vigsp_u16;
typedef unsigned int vigsp_u32;
typedef unsigned long long vigsp_u64;

typedef vigsp_u32 vigsp_bool;
typedef vigsp_u32 vigsp_surface_id;
typedef vigsp_u32 vigsp_offset;
typedef vigsp_u32 vigsp_color;
typedef vigsp_u32 vigsp_fence_seq;

typedef enum
{
    /*
     * These command are guaranteed to sync on host, i.e.
     * no fence is required.
     * @{
     */
    vigsp_cmd_init = 0x0,
    vigsp_cmd_reset = 0x1,
    vigsp_cmd_exit = 0x2,
    vigsp_cmd_set_root_surface = 0x3,
    /*
     * @}
     */
    /*
     * These commands are executed asynchronously.
     * @{
     */
    vigsp_cmd_create_surface = 0x4,
    vigsp_cmd_destroy_surface = 0x5,
    vigsp_cmd_update_vram = 0x6,
    vigsp_cmd_update_gpu = 0x7,
    vigsp_cmd_copy = 0x8,
    vigsp_cmd_solid_fill = 0x9,
    vigsp_cmd_set_plane = 0xA,
    vigsp_cmd_ga_copy = 0xB
    /*
     * @}
     */
} vigsp_cmd;

typedef enum
{
    vigsp_surface_bgrx8888 = 0x0,
    vigsp_surface_bgra8888 = 0x1,
} vigsp_surface_format;

typedef enum
{
    vigsp_plane_bgrx8888 = 0x0,
    vigsp_plane_bgra8888 = 0x1,
    vigsp_plane_nv21 = 0x2,
    vigsp_plane_nv42 = 0x3,
    vigsp_plane_nv61 = 0x4,
    vigsp_plane_yuv420 = 0x5
} vigsp_plane_format;

typedef enum
{
    vigsp_rotation0   = 0x0,
    vigsp_rotation90  = 0x1,
    vigsp_rotation180 = 0x2,
    vigsp_rotation270 = 0x3
} vigsp_rotation;

#pragma pack(1)

struct vigsp_point
{
    vigsp_u32 x;
    vigsp_u32 y;
};

struct vigsp_size
{
    vigsp_u32 w;
    vigsp_u32 h;
};

struct vigsp_rect
{
    struct vigsp_point pos;
    struct vigsp_size size;
};

struct vigsp_copy
{
    struct vigsp_point from;
    struct vigsp_point to;
    struct vigsp_size size;
};

struct vigsp_cmd_batch_header
{
    /*
     * Fence sequence requested by this batch.
     * 0 for none.
     */
    vigsp_fence_seq fence_seq;

    /*
     * Batch size starting from batch header.
     * Can be 0.
     */
    vigsp_u32 size;
};

struct vigsp_cmd_request_header
{
    vigsp_cmd cmd;

    /*
     * Request size starting from request header.
     */
    vigsp_u32 size;
};

/*
 * cmd_init
 *
 * First command to be sent, client passes its protocol version
 * and receives server's in response. If 'client_version' doesn't match
 * 'server_version' then initialization is considered failed. This
 * is typically called on target's DRM driver load.
 *
 * @{
 */

struct vigsp_cmd_init_request
{
    vigsp_u32 client_version;
    vigsp_u32 server_version;
};

/*
 * @}
 */

/*
 * cmd_reset
 *
 * Destroys all surfaces but root surface, this typically happens
 * or DRM's lastclose.
 *
 * @{
 * @}
 */

/*
 * cmd_exit
 *
 * Destroys all surfaces and transitions into uninitialized state, this
 * typically happens when target's DRM driver gets unloaded.
 *
 * @{
 * @}
 */

/*
 * cmd_create_surface
 *
 * Called for each surface created. Client passes 'id' of the surface,
 * all further operations must be carried out using this is. 'id' is
 * unique across whole target system.
 *
 * @{
 */

struct vigsp_cmd_create_surface_request
{
    vigsp_u32 width;
    vigsp_u32 height;
    vigsp_u32 stride;
    vigsp_surface_format format;
    vigsp_surface_id id;
};

/*
 * @}
 */

/*
 * cmd_destroy_surface
 *
 * Destroys the surface identified by 'id'. Surface 'id' may not be used
 * after this call and its id can be assigned to some other surface right
 * after this call.
 *
 * @{
 */

struct vigsp_cmd_destroy_surface_request
{
    vigsp_surface_id id;
};

/*
 * @}
 */

/*
 * cmd_set_root_surface
 *
 * Sets surface identified by 'id' as new root surface. Root surface is the
 * one that's displayed on screen. Root surface resides in VRAM
 * all the time if 'scanout' is true.
 *
 * Pass 0 as id in order to reset the root surface.
 *
 * @{
 */

struct vigsp_cmd_set_root_surface_request
{
    vigsp_surface_id id;
    vigsp_bool scanout;
    vigsp_offset offset;
};

/*
 * @}
 */

/*
 * cmd_update_vram
 *
 * Updates 'sfc_id' in vram.
 *
 * @{
 */

struct vigsp_cmd_update_vram_request
{
    vigsp_surface_id sfc_id;
    vigsp_offset offset;
};

/*
 * @}
 */

/*
 * cmd_update_gpu
 *
 * Updates 'sfc_id' in GPU.
 *
 * @{
 */

struct vigsp_cmd_update_gpu_request
{
    vigsp_surface_id sfc_id;
    vigsp_offset offset;
    vigsp_u32 num_entries;
    struct vigsp_rect entries[0];
};

/*
 * @}
 */

/*
 * cmd_copy
 *
 * Copies parts of surface 'src_id' to
 * surface 'dst_id'.
 *
 * @{
 */

struct vigsp_cmd_copy_request
{
    vigsp_surface_id src_id;
    vigsp_surface_id dst_id;
    vigsp_u32 num_entries;
    struct vigsp_copy entries[0];
};

/*
 * @}
 */

/*
 * cmd_solid_fill
 *
 * Fills surface 'sfc_id' with color 'color' at 'entries'.
 *
 * @{
 */

struct vigsp_cmd_solid_fill_request
{
    vigsp_surface_id sfc_id;
    vigsp_color color;
    vigsp_u32 num_entries;
    struct vigsp_rect entries[0];
};

/*
 * @}
 */

/*
 * cmd_set_plane
 *
 * Assigns surfaces 'surfaces' to plane identified by 'plane'.
 *
 * Pass 0 as surfaces[0] in order to disable the plane.
 *
 * @{
 */

struct vigsp_cmd_set_plane_request
{
    vigsp_u32 plane;
    vigsp_u32 width;
    vigsp_u32 height;
    vigsp_plane_format format;
    vigsp_surface_id surfaces[4];
    struct vigsp_rect src_rect;
    vigsp_s32 dst_x;
    vigsp_s32 dst_y;
    struct vigsp_size dst_size;
    vigsp_s32 z_pos;
    vigsp_bool hflip;
    vigsp_bool vflip;
    vigsp_rotation rotation;
};

/*
 * @}
 */

/*
 * cmd_ga_copy
 *
 * Copies part of surface 'src_id' to
 * surface 'dst_id' given surface
 * sizes.
 *
 * @{
 */

struct vigsp_cmd_ga_copy_request
{
    vigsp_surface_id src_id;
    vigsp_bool src_scanout;
    vigsp_offset src_offset;
    vigsp_u32 src_stride;
    vigsp_surface_id dst_id;
    vigsp_u32 dst_stride;
    struct vigsp_copy entry;
};

/*
 * @}
 */

#pragma pack()

#endif
