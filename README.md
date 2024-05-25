# GQUIC_043_decrypt
这是一个用于解密GQUIC协议Q043版本数据包的工具，基于[gquiche](https://github.com/bilibili/quiche)实现，解密数据包的部分在`gquiche/quic/proto_test`目录下。 
该工具目前只是一个demo玩具，可能会存在或多或少的BUG。

## 环境准备  
1.  安装下列依赖库
```bash
apt-get install cmake build-essential protobuf-compiler libprotobuf-dev golang-go libunwind-dev libicu-dev
```
2. 编译安装[pcap pp库](https://github.com/seladb/PcapPlusPlus)
3. 拉取源码
```bash
git clone https://github.com/aazhuliang/GQUIC_043_decrypt.git
git submodule update --init
```
## 编译  
```bash
mkdir build && cd build  
cmkae -DPCAPPP_INCLUDE_DIRS=xxx -DPCAPPP_LIBRARY_DIRS=xxx ..
make -jx
```
## 使用方法
先修改config.h中的配置项
```bash
./quic_proto_test
python3 decode.py
```
  
## 客户端和服务端使用方法
- A sample quic server and client implementation are provided in quiche. To use these you should build the binaries.

```bash
cd build
make simple_quic_server simple_quic_client
cd -
```

- Download a copy of www.example.org, which we will serve locally using the simple_quic_server binary.

```bash
mkdir -p /data/quic-root
wget -p --save-headers https://www.example.org -P /data/quic-root
```

- In order to run the simple_quic_server, you will need a valid certificate, and a private key is pkcs8 format. If you don't have one, there are scripts to generate them.

```bash
cd utils
./generate-certs.sh
mkdir -p /data/quic-cert
mv ./out/* /data/quic-cert/
cd -
```

- Run the quic server

```bash
./build/simple_quic_server \
  --quic_response_cache_dir=/data/quic-root/ \
  --certificate_file=/data/quic-cert/leaf_cert.pem \
  --key_file=/data/quic-cert/leaf_cert.pkcs8
```

- Request the file with quic client

```bash
./build/simple_quic_client \
  --disable_certificate_verification=true \
  --host=127.0.0.1 --port=6121 \
  "https://www.example.org/index.html"
```

You can also use chormium-based browsers to access simple_quic_server at `127.0.0.1:6121`, and check the request/response protocol by DevTools -> Network panel.
