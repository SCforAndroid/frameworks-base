LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_PACKAGE_NAME := cp_shared_apk

LOCAL_SRC_FILES := $(call all-subdir-java-files)

LOCAL_CERTIFICATE := shared

include $(FrameworkServicesTests_BUILD_PACKAGE)
