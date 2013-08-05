LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_PACKAGE_NAME := cp_release_apk

LOCAL_SRC_FILES := $(call all-subdir-java-files)

include $(FrameworkServicesTests_BUILD_PACKAGE)
