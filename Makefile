COMPONENT=HW3AppC
BUILD_EXTRA_DEPS = HW3Msg.py HW3Msg.class
CLEAN_EXTRA = HW3Msg.pyc HW3Msg.py HW3Msg.class HW3Msg.java

HW3Msg.py: HW3.h
	mig python -target=$(PLATFORM) $(CFLAGS) -python-classname=HW3Msg HW3.h   hw3_msg -o $@

HW3Msg.class: HW3Msg.java
	javac HW3Msg.java
        
HW3Msg.java: HW3.h
	mig java -target=$(PLATFORM) $(CFLAGS) -java-classname=HW3Msg HW3.h   hw3_msg -o $@

include $(MAKERULES)

