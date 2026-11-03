packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "output_directory" {
  type    = string
  default = "output/zitadel"
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

variable "zitadel_version" {
  type    = string
  default = "v2.71.19"
}

variable "zitadel_sha256" {
  type        = string
  default     = "1ae64de1db1b0796e0962255e4dd335ee7bb7af12720c6fa04dda2f4c1c01b64"
  description = "sha256 of zitadel-linux-amd64.tar.gz, equal to the published checksums.txt of the release"
}

source "qemu" "zitadel" {
  iso_url          = "${var.image_base_url}/noble-server-cloudimg-amd64.img"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "12G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = true
  memory           = 2048
  cpus             = 2
  output_directory = var.output_directory
  vm_name          = "zitadel.qcow2"
  cd_label         = "cidata"
  cd_content = {
    "meta-data" = "instance-id: ostyr-packer-build\n"
    "user-data" = "#cloud-config\nssh_pwauth: false\nusers:\n  - name: ubuntu\n    lock_passwd: true\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - ${var.ssh_public_key}\n"
  }
  communicator         = "ssh"
  ssh_username         = "ubuntu"
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "10m"
  shutdown_command     = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.zitadel"]

  provisioner "file" {
    sources     = ["${path.root}/zitadel/zitadel.service", "${path.root}/zitadel/ostyr-zitadel-provision"]
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install postgresql openssl jq curl ca-certificates",
      "sudo systemctl disable postgresql",
      "curl --fail --silent --show-error --location --output /tmp/zitadel.tar.gz https://github.com/zitadel/zitadel/releases/download/${var.zitadel_version}/zitadel-linux-amd64.tar.gz",
      "echo '${var.zitadel_sha256}  /tmp/zitadel.tar.gz' | sha256sum --check -",
      "tar -xzf /tmp/zitadel.tar.gz -C /tmp",
      "sudo install -m 755 /tmp/zitadel-linux-amd64/zitadel /usr/local/bin/zitadel",
      "sudo install -m 755 /tmp/ostyr-zitadel-provision /usr/local/sbin/ostyr-zitadel-provision",
      "sudo install -m 644 /tmp/zitadel.service /etc/systemd/system/zitadel.service",
      "rm -rf /tmp/zitadel.tar.gz /tmp/zitadel-linux-amd64 /tmp/ostyr-zitadel-provision /tmp/zitadel.service",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
