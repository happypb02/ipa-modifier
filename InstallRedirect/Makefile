export THEOS=/opt/theos
export THEOS_DEVICE_IP=localhost
export THEOS_DEVICE_PORT=2222

INSTALL_TARGET_PROCESSES = DumpApp

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = InstallRedirect

InstallRedirect_FILES = Tweak.x
InstallRedirect_CFLAGS = -fobjc-arc
InstallRedirect_FRAMEWORKS = UIKit
InstallRedirect_PRIVATE_FRAMEWORKS =

include $(THEOS_MAKE_PATH)/tweak.mk
