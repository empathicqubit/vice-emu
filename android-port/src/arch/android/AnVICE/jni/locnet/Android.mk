LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := vice

CG_SUBDIRS := .

# Add more subdirs here, like src/subdir1 src/subdir2

MY_PATH := $(LOCAL_PATH)

CG_SRCDIR := $(LOCAL_PATH)

LOCAL_CFLAGS := -DANDROID_COMPILE

LOCAL_C_INCLUDES :=	$(LOCAL_PATH)/include \
				$(LOCAL_PATH)/../sdl/include \
				$(LOCAL_PATH)/../../../../../../src/ \
				$(LOCAL_PATH)/../../../../../../src/arch/sdl \
				$(LOCAL_PATH)/../.. \
				$(LOCAL_PATH)

LOCAL_PATH := $(MY_PATH)

LOCAL_CPPFLAGS := $(LOCAL_CFLAGS)
LOCAL_CXXFLAGS := $(LOCAL_CFLAGS)

#Change C++ file extension as appropriate
LOCAL_CPP_EXTENSION := .cpp

LOCAL_SRC_FILES := $(foreach F, $(CG_SUBDIRS), $(addprefix $(F)/,$(notdir $(wildcard $(LOCAL_PATH)/$(F)/*.cpp))))

LOCAL_STATIC_LIBRARIES := locnet_al vice_main vice_x64 vice_common vice_driver vice_vicii vice_main vice_common vice_driver
#LOCAL_LDLIBS := -ljnigraphics
LOCAL_LDLIBS := -lz -llog


LOCAL_ARM_MODE := arm

include $(BUILD_SHARED_LIBRARY)
