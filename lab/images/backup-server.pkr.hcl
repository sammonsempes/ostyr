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
  default = "output/backup-server"
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

source "qemu" "backup_server" {
  iso_url          = "${var.image_base_url}/noble-server-cloudimg-amd64.img"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "10G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = var.accelerator
  headless         = true
  memory           = 2048
  cpus             = 2
  output_directory = var.output_directory
  vm_name          = "backup-server.qcow2"
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
  sources = ["source.qemu.backup_server"]

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent restic borgbackup",
      "sudo adduser --system --group --home /srv/backups --shell /bin/bash backupsvc",
      "sudo install -d -m 700 -o backupsvc -g backupsvc /srv/backups/.ssh",
      "sudo install -d -m 750 -o backupsvc -g backupsvc /srv/backups/restic /srv/backups/borg",
      "sudo passwd -l backupsvc",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
