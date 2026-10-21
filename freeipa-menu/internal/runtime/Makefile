CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now

all: build/pam_shared_workspace.so build/shared-workspace-greeter

build/pam_shared_workspace.so: src/pam_shared_workspace.c
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) -o $@ $< -lpam

build/shared-workspace-greeter: src/shared_workspace_greeter.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $$(pkg-config --cflags --libs gtk+-3.0 liblightdm-gobject-1 x11)

clean:
	rm -f build/pam_shared_workspace.so build/shared-workspace-greeter build/pam-probe

.PHONY: all clean
