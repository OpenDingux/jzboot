TARGET := jzboot

CFLAGS := -O2
LDLIBS := -lusb-1.0

CC := $(CROSS_COMPILE)gcc

OBJS := $(TARGET).o

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
