# Copyright (C) 2026  Henrique Almeida
# This file is part of tddns.
#
# tddns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# tddns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with tddns.  If not, see <https://www.gnu.org/licenses/>.

TARGET      := tddns
SRC         := tddns.c
CC          := gcc
PKG_CONF    := pkg-config
STATIC      ?= 0
CFLAGS      := -std=c23 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow \
               -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
               -D_POSIX_C_SOURCE=200809L
LDFLAGS     := -Wl,-z,relro,-z,now -Wl,-z,noexecstack
CURL_CFLAGS := $(shell $(PKG_CONF) --cflags libcurl)
ifeq ($(STATIC), 1)
    LIBS    := $(shell $(PKG_CONF) --libs --static libcurl)
    LDFLAGS += -static -static-libgcc
else
    LIBS    := $(shell $(PKG_CONF) --libs libcurl)
endif

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(CURL_CFLAGS) $(LDFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
