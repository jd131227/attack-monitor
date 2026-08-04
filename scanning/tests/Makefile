# Makefile - build the C core into the shared library libmonitor_core.so
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -fPIC
TARGET   = libmonitor_core.so
SRC      = monitor_core.c

.PHONY: all clean test pytest check

all: $(TARGET)

$(TARGET): $(SRC) monitor_core.h
	$(CC) $(CFLAGS) -shared -o $@ $(SRC)

# C unit tests (test_core.c)
test: $(SRC) monitor_core.h test_core.c
	$(CC) $(CFLAGS) -I. -o /tmp/monitor_test test_core.c $(SRC) && /tmp/monitor_test

# Python tests (firewall is fully mocked - no real FW is ever touched)
pytest: $(TARGET)
	python3 -m pytest -q

# Build + both test suites
check: test pytest

clean:
	rm -f $(TARGET) /tmp/monitor_test
