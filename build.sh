#!/bin/sh

set -xe

docker build --tag x509test - < Dockerfile

cat >_go.sh <<END
#!/bin/bash
set -xe

pushd /sources

pushd der-ascii/
go install ./...
popd

export PATH=$PATH:/go/bin

pushd x509test
make
popd

chown --reference=build.sh -R x509test
END
chmod u+x _go.sh

docker run --volume $(pwd):/sources x509test bash /sources/_go.sh
python3 gentests.py
