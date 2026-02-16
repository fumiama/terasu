<img height="400" align="right" src="https://github.com/user-attachments/assets/5d038fd3-0db0-489a-bd2d-f50591d34660">

<div align="center">

# TeRaSu (TRS)

よの光遍く空へ照しつつ

土棲むものは孰れか見ゆや

![counter](https://counter.seku.su/cmoe?name=trs&theme=mb)

</div>

## Usage

```go
tls.Client(terasu.NewConn(conn), &tls.Config{
    ServerName: host,
}).Handshake()
```

## Custom Plugin

Custom plugin code is located in the `ext/custom` directory. You can write and build your own plugin.

1. Write your plugin code in the `ext/custom` directory
2. Build the plugin:

```bash
go build -o terasu.plugin.so -buildmode=plugin -ldflags="-s -w" -trimpath ./ext/custom
```

### Example 1. Build for OpenWrt arm64
```bash
sudo apt-get update
sudo apt-get install -y build-essential module-assistant gcc-9-multilib-i686-linux-gnu g++-9-multilib-i686-linux-gnu
wget -nv https://downloads.openwrt.org/releases/23.05.3/targets/ipq807x/generic/openwrt-sdk-23.05.3-ipq807x-generic_gcc-12.3.0_musl.Linux-x86_64.tar.xz
tar -xJf openwrt-sdk-23.05.3-ipq807x-generic_gcc-12.3.0_musl.Linux-x86_64.tar.xz
mv openwrt-sdk-23.05.3-ipq807x-generic_gcc-12.3.0_musl.Linux-x86_64 op23053-ipq807x
rm openwrt-sdk-23.05.3-ipq807x-generic_gcc-12.3.0_musl.Linux-x86_64.tar.xz

PATH=$PATH:`pwd`/op23053-ipq807x/staging_dir/toolchain-aarch64_cortex-a53_gcc-12.3.0_musl/bin/
export PATH
export STAGING_DIR=`pwd`/op23053-ipq807x/staging_dir/toolchain-aarch64_cortex-a53_gcc-12.3.0_musl/
export CGO_CFLAGS=$CGO_CFLAGS" -fuse-ld=bfd"
echo $CGO_CFLAGS
export CGO_LDFLAGS=$CGO_LDFLAGS" -fuse-ld=bfd"
echo $CGO_LDFLAGS
export GOGCCFLAGS=$GOGCCFLAGS" -fuse-ld=bfd"
echo $GOGCCFLAGS
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 GOARM=8 CC=aarch64-openwrt-linux-gcc CXX=aarch64-openwrt-linux-g++ AR=aarch64-openwrt-linux-ar go build -o terasu.plugin.so -buildmode=plugin -ldflags="-s -w" -trimpath ./ext/custom
```
