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
  default = "output/k3s-node"
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

variable "k3s_release" {
  type    = string
  default = "v1.37.1%2Bk3s1"
}

variable "k3s_sha256" {
  type        = string
  default     = "92b94582eb7b34a8cf532e6006842b9ed215a6783cf56a3dd6271fd35243b2c0"
  description = "sha256 of the k3s binary, equal to sha256sum-amd64.txt of the release"
}

variable "k3s_airgap_sha256" {
  type        = string
  default     = "865b2a63ad7a63fc0db17b7fc2985bf4ae11d5ae93ca1472be6218d20aeb6b23"
  description = "sha256 of k3s-airgap-images-amd64.tar.zst, equal to sha256sum-amd64.txt of the release"
}

source "qemu" "k3s_node" {
  iso_url          = "${var.image_base_url}/noble-server-cloudimg-amd64.img"
  iso_checksum     = var.image_checksum
  disk_image       = true
  use_backing_file = false
  disk_size        = "16G"
  disk_compression = true
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = true
  memory           = 2048
  cpus             = 2
  output_directory = var.output_directory
  vm_name          = "k3s-node.qcow2"
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
  sources = ["source.qemu.k3s_node"]

  provisioner "file" {
    sources     = ["${path.root}/k3s-node/k3s.service", "${path.root}/k3s-node/ostyr-k3s-start"]
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent curl ca-certificates iptables",
      "curl --fail --silent --show-error --location --output /tmp/k3s https://github.com/k3s-io/k3s/releases/download/${var.k3s_release}/k3s",
      "echo '${var.k3s_sha256}  /tmp/k3s' | sha256sum --check -",
      "curl --fail --silent --show-error --location --output /tmp/airgap.tar.zst https://github.com/k3s-io/k3s/releases/download/${var.k3s_release}/k3s-airgap-images-amd64.tar.zst",
      "echo '${var.k3s_airgap_sha256}  /tmp/airgap.tar.zst' | sha256sum --check -",
      "sudo install -m 755 /tmp/k3s /usr/local/bin/k3s",
      "sudo ln -s k3s /usr/local/bin/kubectl",
      "sudo ln -s k3s /usr/local/bin/crictl",
      "sudo install -d -m 755 /var/lib/rancher/k3s/agent/images",
      "sudo install -m 644 /tmp/airgap.tar.zst /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst",
      "sudo install -m 644 /tmp/k3s.service /etc/systemd/system/k3s.service",
      "sudo install -m 755 /tmp/ostyr-k3s-start /usr/local/sbin/ostyr-k3s-start",
      "sudo systemctl daemon-reload",
      "rm -f /tmp/k3s /tmp/airgap.tar.zst /tmp/k3s.service /tmp/ostyr-k3s-start",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
