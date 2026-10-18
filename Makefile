UI_ADDR ?= 127.0.0.1:8080
ADDR ?= 127.0.0.1:7000
WHO ?= alice
FUZZ_SECS ?= 600
JANUS = cargo run --release -q -p janus-cli --
OPEN = $(shell command -v open || command -v xdg-open)
TARGET = $(or $(CARGO_TARGET_DIR),target)
LIB = $(TARGET)/release/libjanus_ffi.$(if $(filter Darwin,$(shell uname)),dylib,so)
BINDGEN = cargo run --release -q -p janus-ffi --features cli --bin uniffi-bindgen -- generate --library $(LIB)
APPLE = apps/apple/Generated
ANDROID = apps/android/app/src
# Android Studio's SDK, else Homebrew's command-line tools.
export ANDROID_HOME ?= $(firstword $(wildcard $(HOME)/Library/Android/sdk /opt/homebrew/share/android-commandlinetools))
export ANDROID_NDK_HOME ?= $(lastword $(sort $(wildcard $(ANDROID_HOME)/ndk/*)))
export JAVA_HOME ?= $(firstword $(wildcard /opt/homebrew/opt/openjdk@17))
ADB = $(ANDROID_HOME)/platform-tools/adb
SDK_TOOLS = $(ANDROID_HOME)/cmdline-tools/latest/bin
AVD ?= janus
AVD_IMAGE = system-images;android-35;google_apis;arm64-v8a
# The first iPhone of the newest simulator runtime, by id: names repeat across runtimes.
SIM ?= $(shell xcrun simctl list devices available -j 2>/dev/null | python3 -c "import json, re, sys; d = json.load(sys.stdin)['devices']; print(next(x['udid'] for r in sorted(d, reverse=True) for x in d[r] if re.fullmatch(r'iPhone \d+', x['name'])))" 2>/dev/null)
IOS_APP = $(TARGET)/xcode/Build/Products/Debug-iphonesimulator/Janus.app

.DEFAULT_GOAL := help
.PHONY: help demo ui mailbox invite join chat test lint check fuzz bindings apple android \
	android-emulator android-run desktop ios-run

help: ## List the commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-16s %s\n", $$1, $$2}'

demo: check ui ## Lint and test everything, then open the web demo

ui: ## Web demo: two chats and the processes underneath (UI_ADDR=127.0.0.1:8080)
	cargo build --release -q -p janus-cli
	@(sleep 1 && $(OPEN) http://$(UI_ADDR)) &
	$(JANUS) ui $(UI_ADDR)

mailbox: ## Terminal chat, step 1: the mailbox (ADDR=127.0.0.1:7000)
	cargo run --release -q -p janus-mailbox -- $(ADDR)

invite: ## Terminal chat, step 2 in another terminal: Alice invites (state in .janus/alice)
	JANUS_DIR=.janus/alice $(JANUS) invite $(ADDR)

join: ## Terminal chat, step 3 in a third terminal, within 10 minutes: Bob answers
	JANUS_DIR=.janus/bob $(JANUS) join $(ADDR)

chat: ## Terminal chat, after quitting: back to the saved contacts (WHO=alice or bob)
	JANUS_DIR=.janus/$(WHO) $(JANUS) chat $(ADDR)

test: ## Run all tests, the client's crash test included
	cargo test --release

lint: ## Check formatting and clippy
	cargo fmt --check
	cargo clippy --all-targets

check: lint test ## Lint and test

fuzz: ## Fuzz receive, import and the handshake, FUZZ_SECS each (needs nightly and cargo-fuzz)
	cd fuzz && for t in receive import handshake; do \
		cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECS) || exit 1; \
	done

bindings: ## Swift and Kotlin bindings of janus-ffi, in target/bindings
	cargo build --release -q -p janus-ffi
	$(BINDGEN) --language swift --out-dir target/bindings/swift
	$(BINDGEN) --language kotlin --out-dir target/bindings/kotlin

apple: bindings ## iOS app: Rust library, Swift bindings and Janus.xcodeproj in apps/apple (needs Xcode, xcodegen)
	rustup target add aarch64-apple-ios aarch64-apple-ios-sim
	IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --release -q -p janus-ffi --target aarch64-apple-ios
	IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --release -q -p janus-ffi --target aarch64-apple-ios-sim
	rm -rf $(APPLE) && mkdir -p $(APPLE)/include $(APPLE)/ios $(APPLE)/ios-sim
	cp target/bindings/swift/janus_ffi.swift $(APPLE)/
	cp target/bindings/swift/janus_ffiFFI.h $(APPLE)/include/
	cp target/bindings/swift/janus_ffiFFI.modulemap $(APPLE)/include/module.modulemap
	cp $(TARGET)/aarch64-apple-ios/release/libjanus_ffi.a $(APPLE)/ios/
	cp $(TARGET)/aarch64-apple-ios-sim/release/libjanus_ffi.a $(APPLE)/ios-sim/
	-cp mailbox.der $(APPLE)/mailbox.der
	cd apps/apple && xcodegen

android: bindings ## Android app: Rust libraries and Kotlin bindings in apps/android (needs the NDK, cargo-ndk)
	rustup target add aarch64-linux-android x86_64-linux-android
	cargo ndk -t arm64-v8a -t x86_64 -o $(ANDROID)/main/jniLibs build --release -p janus-ffi
	mkdir -p $(ANDROID)/main/java/uniffi/janus_ffi $(ANDROID)/debug/assets
	cp target/bindings/kotlin/uniffi/janus_ffi/janus_ffi.kt $(ANDROID)/main/java/uniffi/janus_ffi/
	-cp mailbox.der $(ANDROID)/debug/assets/mailbox.der

android-emulator: ## Start an Android emulator and wait for it (AVD=janus; another name is a second phone)
	@$(SDK_TOOLS)/avdmanager list avd -c 2>/dev/null | grep -qx '$(AVD)' || { \
		$(SDK_TOOLS)/sdkmanager --install emulator '$(AVD_IMAGE)' && \
		echo no | $(SDK_TOOLS)/avdmanager -s create avd -n '$(AVD)' -k '$(AVD_IMAGE)' -d pixel_7; }
	@for s in $$($(ADB) devices | awk '/^emulator-/ {print $$1}'); do \
		if [ "$$($(ADB) -s $$s emu avd name | head -1 | tr -d '\r')" = '$(AVD)' ]; then \
			echo "$(AVD) already runs as $$s"; exit 0; fi; \
	done; \
	port=$$((5554 + 2 * $$($(ADB) devices | grep -c '^emulator-'))); \
	nohup $(ANDROID_HOME)/emulator/emulator -avd '$(AVD)' -port $$port -no-boot-anim >/dev/null 2>&1 & \
	$(ADB) -s emulator-$$port wait-for-device; \
	until [ "$$($(ADB) -s emulator-$$port shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do \
		sleep 2; done; \
	echo "$(AVD) runs as emulator-$$port"

android-run: android ## Install and open the Android app on every running emulator or phone (after `make mailbox`)
	@$(ADB) devices | grep -q 'device$$' || $(MAKE) -s android-emulator
	cd apps/android && ./gradlew -q installDebug
	@for s in $$($(ADB) devices | awk 'NR > 1 && $$2 == "device" {print $$1}'); do \
		$(ADB) -s $$s shell am start -n org.janusknot.janus/.MainActivity >/dev/null && echo "opened on $$s"; \
	done

desktop: ## Desktop app (Windows, Linux; macOS for testing) on the development mailbox (after `make mailbox`)
	JANUS_DEV_MAILBOX=$(ADDR) JANUS_DEV_CERT=mailbox.der cargo run -q -p janus-desktop

ios-run: apple ## Build the iOS app and open it in the simulator (SIM="iPhone 17", after `make mailbox`)
	xcodebuild -quiet -project apps/apple/Janus.xcodeproj -scheme Janus -configuration Debug \
		-destination 'generic/platform=iOS Simulator' ARCHS=arm64 -derivedDataPath $(TARGET)/xcode build
	-xcrun simctl boot '$(SIM)'
	-open -a Simulator 2>/dev/null || open "$$(xcode-select -p)/Applications/Simulator.app" 2>/dev/null || \
		open "$$(xcode-select -p)/../Applications/DeviceHub.app"
	xcrun simctl install '$(SIM)' $(IOS_APP)
	xcrun simctl launch '$(SIM)' org.janusknot.janus
