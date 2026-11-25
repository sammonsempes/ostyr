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
  default = "output/rustdesk-relay"
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

variable "hbbs_binary" {
  type        = string
  description = "build.sh passes hbbs extracted from the pinned rustdesk/rustdesk-server image, already checked against the rustdesk-hbbs row of pins.tsv"
}

variable "hbbr_binary" {
  type        = string
  description = "build.sh passes hbbr extracted from the pinned rustdesk/rustdesk-server image, already checked against the rustdesk-hbbr row of pins.tsv"
}

variable "hbbs_sha256" {
  type        = string
  default     = "374c821722b04f6d7ef063c78bc5b4db7109b8b9613508822d803e31fdc5b625"
  description = "sha256 of hbbs 1.1.16 (linux/amd64 layer of the pinned image index); checked again in the VM"
}

variable "hbbr_sha256" {
  type        = string
  default     = "3ad04953242db5a9a78d45d41d13b9c6ecff651881e3a7f594f8b36a321e2457"
  description = "sha256 of hbbr 1.1.16 (linux/amd64 layer of the pinned image index); checked again in the VM"
}

source "qemu" "rustdesk-relay" {
  iso_url          = "${var.image_base_url}/noble-server-cloudimg-amd64.img"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "8G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = var.accelerator
  headless         = true
  memory           = 2048
  cpus             = 2
  output_directory = var.output_directory
  vm_name          = "rustdesk-relay.qcow2"
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
  sources = ["source.qemu.rustdesk-relay"]

  provisioner "file" {
    sources = [
      var.hbbs_binary,
      var.hbbr_binary,
      "${path.root}/rustdesk-relay/rustdesk-hbbs.service",
      "${path.root}/rustdesk-relay/rustdesk-hbbr.service",
      "${path.root}/rustdesk-relay/ostyr-rustdesk-start",
      "${path.root}/rustdesk-relay/ostyr-rustdesk.nft",
    ]
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent nftables iproute2",
      "echo '${var.hbbs_sha256}  /tmp/hbbs-binary' | sha256sum --check -",
      "echo '${var.hbbr_sha256}  /tmp/hbbr-binary' | sha256sum --check -",
      "sudo install -d -m 755 -o root -g root /opt/ostyr /opt/ostyr/rustdesk",
      "sudo install -m 755 -o root -g root /tmp/hbbs-binary /opt/ostyr/rustdesk/hbbs",
      "sudo install -m 755 -o root -g root /tmp/hbbr-binary /opt/ostyr/rustdesk/hbbr",
      "sudo useradd --system --home-dir /var/lib/rustdesk --no-create-home --shell /usr/sbin/nologin rustdesk",
      "sudo install -m 755 /tmp/ostyr-rustdesk-start /usr/local/sbin/ostyr-rustdesk-start",
      "sudo install -m 644 /tmp/rustdesk-hbbs.service /etc/systemd/system/rustdesk-hbbs.service",
      "sudo install -m 644 /tmp/rustdesk-hbbr.service /etc/systemd/system/rustdesk-hbbr.service",
      "sudo install -m 644 /tmp/ostyr-rustdesk.nft /etc/nftables.conf",
      "sudo nft --check --file /etc/nftables.conf",
      "sudo systemctl enable nftables rustdesk-hbbs rustdesk-hbbr",
      "rm -f /tmp/hbbs-binary /tmp/hbbr-binary /tmp/rustdesk-hbbs.service /tmp/rustdesk-hbbr.service /tmp/ostyr-rustdesk-start /tmp/ostyr-rustdesk.nft",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
