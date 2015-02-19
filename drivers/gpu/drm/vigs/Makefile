#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrastructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y := -Iinclude/drm -Idrivers/gpu/drm/vigs
vigs_drm-y := main.o \
              vigs_driver.o \
              vigs_gem.o \
              vigs_surface.o \
              vigs_execbuffer.o \
              vigs_device.o \
              vigs_mman.o \
              vigs_crtc.o \
              vigs_output.o \
              vigs_framebuffer.o \
              vigs_comm.o \
              vigs_fbdev.o \
              vigs_irq.o \
              vigs_fence.o \
              vigs_fenceman.o \
              vigs_file.o \
              vigs_plane.o \
              vigs_dp.o

obj-$(CONFIG_DRM_VIGS) += vigs_drm.o
