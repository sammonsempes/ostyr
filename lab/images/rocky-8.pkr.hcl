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
  default = "output/rocky-8"
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
  default = "https://dl.rockylinux.org/pub/rocky/8/images/x86_64"
}

variable "image_checksum" {
  type        = string
  default     = "file:https://dl.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM"
  description = "build.sh passes the checksum taken from the GPG-verified CHECKSUM file"
}

source "qemu" "rocky" {
  iso_url          = "${var.image_base_url}/Rocky-8-GenericCloud-Base.latest.x86_64.qcow2"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "10G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = true
  memory           = 2048
  cpus             = 2
  qemuargs         = [["-cpu", "host"]]
  output_directory = var.output_directory
  vm_name          = "rocky-8.qcow2"
  cd_label         = "cidata"
  cd_content = {
    "meta-data" = "instance-id: ostyr-packer-build\n"
    "user-data" = "#cloud-config\nssh_pwauth: false\nusers:\n  - name: rocky\n    lock_passwd: true\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - ${var.ssh_public_key}\n"
  }
  communicator         = "ssh"
  ssh_username         = "rocky"
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "10m"
  shutdown_command     = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.rocky"]

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo dnf -y upgrade --exclude=kernel*",
      "sudo dnf -y install qemu-guest-agent",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l rocky",
      "sudo truncate -s 0 /home/rocky/.ssh/authorized_keys",
      "sudo dnf clean all",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
