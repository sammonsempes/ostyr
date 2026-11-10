packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "build.sh passes kvm or tcg"
}

variable "timeout_factor" {
  type        = number
  default     = 1
  description = "build.sh multiplies the SSH timeout under tcg"
}

variable "output_directory" {
  type    = string
  default = "output/datastore"
}

variable "ssh_public_key" {
  type        = string
  description = "Throwaway public key authorised for the build only"
}

variable "ssh_private_key_file" {
  type        = string
  description = "Private key matching ssh_public_key"
}

variable "image_base_url" {
  type    = string
  default = "https://cloud-images.ubuntu.com/noble/current"
}

variable "image_checksum" {
  type        = string
  default     = "file:https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
  description = "build.sh passes the sha256 taken from the GPG-verified SHA256SUMS"
}

variable "clickhouse_version" {
  type        = string
  default     = "26.8.36.3"
  description = "ClickHouse LTS package version from the official apt repository"
}

variable "clickhouse_key_fingerprint" {
  type        = string
  default     = "3A9EA1193A97B548BE1457D48919F6BD2B48D754"
  description = "Fingerprint of the ClickHouse repository signing key, checked before the key is trusted"
}

variable "nats_version" {
  type    = string
  default = "v2.15.2"
}

variable "nats_sha256" {
  type        = string
  default     = "67cb8e10bc6f0c4b47f75a728529a20953dbae2a4f9a4a52ae8517d65ae303ff"
  description = "sha256 of nats-server-<version>-linux-amd64.tar.gz, equal to the published SHA256SUMS of the release"
}

variable "natscli_version" {
  type    = string
  default = "0.5.1"
}

variable "natscli_sha256" {
  type        = string
  default     = "f8a3e106deebed7afe736b7090359bda3aa62a04b310440bedc1d11a93c0ab4f"
  description = "sha256 of nats-<version>-linux-amd64.zip, equal to the published SHA256SUMS of the release"
}

variable "garage_binary" {
  type        = string
  description = "build.sh passes the cached Garage binary, already checked against the garage row of pins.tsv"
}

variable "garage_sha256" {
  type        = string
  default     = "2ff667286217cd73ebcb1c03af993822365000441dfe31a80cb64c5189a9dea8"
  description = "sha256 of the Garage v2.5.0 static musl binary, equal on the release host and in the dxflrs/garage image layer; checked again in the VM"
}

source "qemu" "datastore" {
  iso_url          = "${var.image_base_url}/noble-server-cloudimg-amd64.img"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "16G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = var.accelerator
  headless         = true
  memory           = 4096
  cpus             = 2
  qemuargs         = [["-cpu", var.accelerator == "kvm" ? "host" : "max"]]
  output_directory = var.output_directory
  vm_name          = "datastore.qcow2"
  cd_label         = "cidata"
  cd_content = {
    "meta-data" = "instance-id: ostyr-packer-build\n"
    "user-data" = "#cloud-config\nssh_pwauth: false\nusers:\n  - name: ubuntu\n    lock_passwd: true\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - ${var.ssh_public_key}\n"
  }
  communicator         = "ssh"
  ssh_username         = "ubuntu"
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "${10 * var.timeout_factor}m"
  shutdown_command     = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.datastore"]

  provisioner "file" {
    sources     = ["${path.root}/datastore/nats-server.service", "${path.root}/datastore/restart-on-failure.conf", "${path.root}/datastore/ostyr-datastore-provision"]
    destination = "/tmp/"
  }

  provisioner "file" {
    sources     = [var.garage_binary, "${path.root}/datastore/garage.service", "${path.root}/datastore/ostyr-garage-tls.service"]
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install postgresql postgresql-client openssl jq curl ca-certificates gnupg unzip stunnel4",
      "sudo systemctl disable --now stunnel4",
      "sudo systemctl disable --now postgresql",
      "curl --fail --silent --show-error --location --output /tmp/clickhouse.key https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key",
      "test \"$(gpg --show-keys --with-colons /tmp/clickhouse.key | awk -F: '$1 == \"fpr\" {print $10; exit}')\" = '${var.clickhouse_key_fingerprint}'",
      "sudo gpg --dearmor --output /usr/share/keyrings/clickhouse-keyring.gpg /tmp/clickhouse.key",
      "echo 'deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb lts main' | sudo tee /etc/apt/sources.list.d/clickhouse.list",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install clickhouse-common-static=${var.clickhouse_version} clickhouse-server=${var.clickhouse_version} clickhouse-client=${var.clickhouse_version}",
      "sudo systemctl disable --now clickhouse-server",
      "sudo install -d /etc/systemd/system/clickhouse-server.service.d /etc/systemd/system/postgresql@.service.d",
      "sudo install -m 644 /tmp/restart-on-failure.conf /etc/systemd/system/clickhouse-server.service.d/ostyr.conf",
      "sudo install -m 644 /tmp/restart-on-failure.conf /etc/systemd/system/postgresql@.service.d/ostyr.conf",
      "curl --fail --silent --show-error --location --output /tmp/nats.tar.gz https://github.com/nats-io/nats-server/releases/download/${var.nats_version}/nats-server-${var.nats_version}-linux-amd64.tar.gz",
      "echo '${var.nats_sha256}  /tmp/nats.tar.gz' | sha256sum --check -",
      "tar -xzf /tmp/nats.tar.gz -C /tmp",
      "sudo install -m 755 /tmp/nats-server-${var.nats_version}-linux-amd64/nats-server /usr/local/bin/nats-server",
      "sudo useradd --system --home-dir /var/lib/nats --shell /usr/sbin/nologin nats",
      "sudo install -d -m 755 /etc/nats",
      "sudo install -m 644 /tmp/nats-server.service /etc/systemd/system/nats-server.service",
      "sudo systemctl daemon-reload",
      "sudo install -d -m 755 /usr/local/share/ostyr-lab/client",
      "curl --fail --silent --show-error --location --output /tmp/natscli.zip https://github.com/nats-io/natscli/releases/download/v${var.natscli_version}/nats-${var.natscli_version}-linux-amd64.zip",
      "echo '${var.natscli_sha256}  /tmp/natscli.zip' | sha256sum --check -",
      "unzip -o -j /tmp/natscli.zip '*/nats' -d /tmp/natscli",
      "sudo install -m 755 /tmp/natscli/nats /usr/local/share/ostyr-lab/client/nats",
      "cd /tmp && apt-get download postgresql-client-16 postgresql-client-common libpq5 && sudo install -m 644 /tmp/postgresql-client-16_*.deb /tmp/postgresql-client-common_*.deb /tmp/libpq5_*.deb /usr/local/share/ostyr-lab/client/",
      "echo '${var.garage_sha256}  /tmp/garage-binary' | sha256sum --check -",
      "sudo install -m 755 /tmp/garage-binary /usr/local/bin/garage",
      "sudo useradd --system --home-dir /var/lib/garage --shell /usr/sbin/nologin garage",
      "sudo install -m 644 /tmp/garage.service /etc/systemd/system/garage.service",
      "sudo install -m 644 /tmp/ostyr-garage-tls.service /etc/systemd/system/ostyr-garage-tls.service",
      "sudo systemctl daemon-reload",
      "sudo install -m 755 /tmp/ostyr-datastore-provision /usr/local/sbin/ostyr-datastore-provision",
      "rm -rf /tmp/*.deb /tmp/clickhouse.key /tmp/nats.tar.gz /tmp/nats-server-* /tmp/natscli* /tmp/ostyr-datastore-provision /tmp/nats-server.service /tmp/restart-on-failure.conf /tmp/garage-binary /tmp/garage.service /tmp/ostyr-garage-tls.service",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
