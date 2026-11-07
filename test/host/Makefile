# Host-side unit tests for the pure-logic parts of presidio-hardened-esp32.
# See README.md in this directory for what is (and is not) covered.
#
#   make -C test/host test
#   make -C test/host test MBEDTLS_CFLAGS=-I/opt/homebrew/include   # macOS/Homebrew

CC ?= cc
ROOT := ../..
BUILD := build

# mbedTLS is used for its headers only (cipher-suite IDs); nothing is linked.
MBEDTLS_CFLAGS ?=

# Kconfig defaults that matter for the compiled sources. TLS hardening is
# left undefined on purpose: that path calls into mbedTLS and is covered by
# the device test app, not here.
KCONFIG_DEFS := \
	-DCONFIG_PRESIDIO_NVS_REDACTION=1 \
	-DCONFIG_PRESIDIO_ANOMALY_MAX_AUTH_FAILURES=5 \
	-DCONFIG_PRESIDIO_INPUT_MAX_WIFI_SSID_LEN=32 \
	-DCONFIG_PRESIDIO_INPUT_MAX_WIFI_PASS_LEN=64 \
	-DCONFIG_PRESIDIO_INPUT_MAX_MQTT_TOPIC_LEN=256 \
	-DCONFIG_PRESIDIO_INPUT_MAX_HTTP_BODY_LEN=4096 \
	-DCONFIG_PRESIDIO_LOG_MAX_EVENTS=64

SANITIZE ?= -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
CFLAGS ?= -std=gnu11 -g -O1 -Wall -Wextra -Wshadow -Wformat=2 -Werror
CPPFLAGS := -I. -Istubs -I$(ROOT)/include $(MBEDTLS_CFLAGS) $(KCONFIG_DEFS)

COMPONENT_SRCS := \
	$(ROOT)/src/presidio_anomaly.c \
	$(ROOT)/src/presidio_input.c \
	$(ROOT)/src/presidio_log.c \
	$(ROOT)/src/presidio_nvs.c \
	$(ROOT)/src/presidio_tls.c

# Shared with the device test app (test/CMakeLists.txt picks up test/*.c).
SHARED_TESTS := \
	$(ROOT)/test/test_anomaly.c \
	$(ROOT)/test/test_input.c \
	$(ROOT)/test/test_log.c \
	$(ROOT)/test/test_nvs_policy.c \
	$(ROOT)/test/test_tls_policy.c

HOST_SRCS := unity_host.c stubs/host_stubs.c test_host_extra.c

SRCS := $(COMPONENT_SRCS) $(SHARED_TESTS) $(HOST_SRCS)
BIN := $(BUILD)/presidio_host_tests

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRCS) $(wildcard *.h stubs/*.h $(ROOT)/include/*.h)
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZE) $(SRCS) -o $@

test: $(BIN)
	$(BIN)

clean:
	rm -rf $(BUILD)
