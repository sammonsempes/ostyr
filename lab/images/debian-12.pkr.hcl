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
  default = "output/debian-12"
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
  default = "https://cloud.debian.org/images/cloud/bookworm/latest"
}

variable "image_checksum" {
  type        = string
  default     = "file:https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
  description = "build.sh passes the sha512 taken from SHA512SUMS"
}

source "qemu" "debian" {
  iso_url          = "${var.image_base_url}/debian-12-genericcloud-amd64.qcow2"
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
  vm_name          = "debian-12.qcow2"
  cd_label         = "cidata"
  cd_content = {
    "meta-data" = "instance-id: ostyr-packer-build\n"
    "user-data" = "#cloud-config\nssh_pwauth: false\nusers:\n  - name: debian\n    lock_passwd: true\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - ${var.ssh_public_key}\n"
  }
  communicator         = "ssh"
  ssh_username         = "debian"
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "${10 * var.timeout_factor}m"
  shutdown_command     = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.debian"]

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l debian",
      "sudo truncate -s 0 /home/debian/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo rm -f /etc/netplan/50-cloud-init.yaml",
      "sudo cloud-init clean --logs --seed",
      "sudo truncate -s 0 /etc/machine-id",
    ]
  }
}
