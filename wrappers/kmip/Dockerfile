FROM ubuntu:20.04

COPY . /go-kms-wrapping

# Set up PyKMIP and run tests.
#
# The last PyKMIP release has been a while, so pull the version from GitHub
# rather than from PyPI.
#
# PyKMIP does not yet support Python > 3.12 (which updates the ssl module)
# so we run on an older Ubuntu version.
RUN true && \
    apt update && \
    DEBIAN_FRONTEND="noninteractive" apt install -y softhsm2 libsofthsm2 golang-go opensc ca-certificates python3-pip python3-dev libffi-dev libssl-dev libsqlite3-dev wget && \
    pip install --user https://github.com/OpenKMIP/PyKMIP/archive/master.zip && \
    wget https://github.com/ovh/okms-cli/releases/download/v0.3.3/okms-cli-linux-x86_64.tar.gz https://github.com/ovh/okms-cli/releases/download/v0.3.3/checksums.txt && \
    echo 'f54d991945fb749099c32938a472ccc86d5f1eb19bf3e2791200dc8994aa6bcd  checksums.txt' | sha256sum -c && \
    sha256sum --ignore-missing -c checksums.txt && \
    tar -xf okms-cli-linux-x86_64.tar.gz -C /bin okms && \
	echo "here" && \
	bash /go-kms-wrapping/wrappers/kmip/pykmip.sh && \
    true
