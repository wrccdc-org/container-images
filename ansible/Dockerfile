FROM jenkins/agent:bullseye-jdk25
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-pip

RUN pip install --break-system-packages "ansible" pyvmomi mitogen requests
COPY requirements.yml /tmp/
RUN ansible-galaxy install -r /tmp/requirements.yml