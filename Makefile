# wa-mini - Minimal WhatsApp Primary Device
# Makefile
#
# Copyright (c) 2025, Renaud Allard <renaud@allard.it>
# BSD 2-Clause License

# Compiler and flags
CC ?= cc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11 -O2 -I./include
LDFLAGS = -lsodium -lcrypto -lm

# Debug build
ifdef DEBUG
CFLAGS += -g -O0 -DDEBUG
endif

# Source files
SRC = src/main.c \
      src/context.c \
      src/control.c \
      src/crypto.c \
      src/noise.c \
      src/dict.c \
      src/xmpp.c \
      src/socket.c \
      src/store.c \
      src/signal.c \
      src/register.c \
      src/companion.c \
      src/version.c \
      src/proto.c

# Object files
OBJ = $(SRC:.c=.o)

# Output binary
TARGET = wa-mini

# Installation paths
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1
SYSCONFDIR = /etc

# Fuzzing compiler and flags
FUZZ_CC = clang
FUZZ_CFLAGS = -g -O1 -fno-omit-frame-pointer \
              -fsanitize=fuzzer,address,undefined \
              -I./include

# Build rules
.PHONY: all clean install uninstall test format lint fuzz fuzz-clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies
src/main.o: include/wa-mini.h include/control.h
src/context.o: include/wa-mini.h include/noise.h include/xmpp.h include/proto.h
src/control.o: include/control.h include/wa-mini.h
src/crypto.o: include/noise.h
src/noise.o: include/noise.h
src/dict.o: include/dict.h
src/xmpp.o: include/xmpp.h include/dict.h
src/socket.o: include/wa-mini.h
src/store.o: include/wa-mini.h
src/proto.o: include/proto.h

clean:
	rm -f src/*.o $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 wa-mini.1 $(DESTDIR)$(MANDIR)/

install-service: install
	# Linux systemd
	@if [ -d /etc/systemd/system ]; then \
		install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system; \
		install -m 644 etc/linux/wa-mini.service $(DESTDIR)$(SYSCONFDIR)/systemd/system/; \
		echo "Installed systemd units. Run:"; \
		echo "  systemctl daemon-reload"; \
		echo "  systemctl enable wa-mini"; \
	fi
	# OpenBSD rc.d
	@if [ -d /etc/rc.d ]; then \
		install -m 755 etc/openbsd/wa-mini $(DESTDIR)/etc/rc.d/; \
		echo "Installed OpenBSD rc.d script. Run:"; \
		echo "  rcctl enable wa_mini"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/wa-mini.1
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/wa-mini.service
	rm -f $(DESTDIR)/etc/rc.d/wa-mini

# Development targets
test:
	@echo "Running tests..."
	@# TODO: Add test targets

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i src/*.c include/*.h; \
	else \
		echo "clang-format not found"; \
	fi

lint:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --inconclusive -I./include src/*.c; \
	else \
		echo "cppcheck not found"; \
	fi

# Debug build shortcut
debug:
	$(MAKE) DEBUG=1 all

# Fuzzing targets
fuzz: fuzz_xmpp fuzz_proto fuzz_noise
	@echo "All fuzz targets built. Run with:"
	@echo "  ./fuzz_xmpp fuzz/corpus/xmpp -dict=fuzz/dictionaries/xmpp.dict"
	@echo "  ./fuzz_proto fuzz/corpus/proto -dict=fuzz/dictionaries/proto.dict"
	@echo "  ./fuzz_noise fuzz/corpus/noise -dict=fuzz/dictionaries/noise.dict"

fuzz_xmpp: fuzz/fuzz_xmpp_decode.c src/xmpp.c src/dict.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ -lsodium

fuzz_proto: fuzz/fuzz_proto_decode.c src/proto.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ -lsodium

fuzz_noise: fuzz/fuzz_noise_read.c src/noise.c src/crypto.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ -lsodium

fuzz-clean:
	rm -f fuzz_xmpp fuzz_proto fuzz_noise
	rm -f crash-* leak-* timeout-*

# Fuzz corpus seeding (generate initial inputs)
fuzz-seed:
	@mkdir -p fuzz/corpus/xmpp fuzz/corpus/proto fuzz/corpus/noise
	@echo "Creating seed corpus..."
	@printf '\xf8\x04iq\x00' > fuzz/corpus/xmpp/iq_empty
	@printf '\xf8\x08presence\x00' > fuzz/corpus/xmpp/presence_empty
	@printf '\x12\x22\x0a\x20' > fuzz/corpus/proto/handshake_hello
	@dd if=/dev/urandom of=fuzz/corpus/noise/random_32 bs=32 count=1 2>/dev/null
	@dd if=/dev/urandom of=fuzz/corpus/noise/random_64 bs=64 count=1 2>/dev/null
	@echo "Seed corpus created"
