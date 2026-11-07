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
  default = "output/attacker"
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

variable "powershell_version" {
  type    = string
  default = "7.6.9"
}

variable "powershell_sha256" {
  type        = string
  default     = "1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b"
  description = "sha256 of powershell-linux-x64.tar.gz, equal to the release hashes.sha256"
}

variable "invoke_atomicredteam_version" {
  type    = string
  default = "v2.3.0"
}

variable "invoke_atomicredteam_sha256" {
  type        = string
  default     = "b374222988739f50cebcb51bb73f478fff951107ff5f0d8680fd6b669cf49b6e"
  description = "sha256 of the GitHub source archive of the tag, computed when pinned"
}

variable "atomics_commit" {
  type    = string
  default = "a8f00488f3be0d6f8a967585848bb3817a590e31"
}

variable "atomics_sha256" {
  type        = string
  default     = "6bdfb4e898dd315adfa66f771c8603fd5b61a35d88db96daaec393d94a9a4a22"
  description = "sha256 of the GitHub source archive of atomics_commit, computed when pinned"
}

variable "powershell_yaml_version" {
  type    = string
  default = "0.4.9"
}

variable "powershell_yaml_sha256" {
  type        = string
  default     = "9148c268709ab46b21835c3ed8502ebdbff4a6dc19e65b7b3dd6b66e9131fd28"
  description = "sha256 of the PSGallery nupkg of powershell_yaml_version, computed when pinned"
}

source "qemu" "attacker" {
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
  vm_name          = "attacker.qcow2"
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
  sources = ["source.qemu.attacker"]

  provisioner "file" {
    sources     = ["${path.root}/attacker/ostyr-attacker-egress", "${path.root}/attacker/ostyr-attacker-egress.service"]
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "cloud-init status --wait",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y install qemu-guest-agent curl ca-certificates nftables libicu74 nmap netcat-openbsd",
      "curl --fail --silent --show-error --location --output /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v${var.powershell_version}/powershell-${var.powershell_version}-linux-x64.tar.gz",
      "echo '${var.powershell_sha256}  /tmp/powershell.tar.gz' | sha256sum --check -",
      "sudo install -d -m 755 /opt/microsoft/powershell/7",
      "sudo tar -xzf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7",
      "sudo chmod 755 /opt/microsoft/powershell/7/pwsh",
      "sudo ln -s /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh",
      "curl --fail --silent --show-error --location --output /tmp/invoke-atomicredteam.tar.gz https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/tags/${var.invoke_atomicredteam_version}.tar.gz",
      "echo '${var.invoke_atomicredteam_sha256}  /tmp/invoke-atomicredteam.tar.gz' | sha256sum --check -",
      "curl --fail --silent --show-error --location --output /tmp/atomics.tar.gz https://github.com/redcanaryco/atomic-red-team/archive/${var.atomics_commit}.tar.gz",
      "echo '${var.atomics_sha256}  /tmp/atomics.tar.gz' | sha256sum --check -",
      "sudo install -d -m 755 /opt/AtomicRedTeam/invoke-atomicredteam",
      "sudo tar -xzf /tmp/invoke-atomicredteam.tar.gz -C /opt/AtomicRedTeam/invoke-atomicredteam --strip-components=1",
      "sudo tar -xzf /tmp/atomics.tar.gz -C /opt/AtomicRedTeam --strip-components=1 --wildcards '*/atomics'",
      "curl --fail --silent --show-error --location --output /tmp/powershell-yaml.nupkg https://www.powershellgallery.com/api/v2/package/powershell-yaml/${var.powershell_yaml_version}",
      "echo '${var.powershell_yaml_sha256}  /tmp/powershell-yaml.nupkg' | sha256sum --check -",
      "sudo python3 -m zipfile -e /tmp/powershell-yaml.nupkg /usr/local/share/powershell/Modules/powershell-yaml/${var.powershell_yaml_version}",
      "sudo pwsh -NoProfile -Command \"Import-Module powershell-yaml -RequiredVersion ${var.powershell_yaml_version}; Get-Command ConvertFrom-Yaml | Out-Null\"",
      "sudo pwsh -NoProfile -Command \"Import-Module /opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force; Get-Command Invoke-AtomicTest | Out-Null\"",
      "sudo install -m 755 /tmp/ostyr-attacker-egress /usr/local/sbin/ostyr-attacker-egress",
      "sudo install -m 644 /tmp/ostyr-attacker-egress.service /etc/systemd/system/ostyr-attacker-egress.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable ostyr-attacker-egress.service",
      "rm -f /tmp/powershell.tar.gz /tmp/invoke-atomicredteam.tar.gz /tmp/atomics.tar.gz /tmp/powershell-yaml.nupkg /tmp/ostyr-attacker-egress /tmp/ostyr-attacker-egress.service",
      "sudo systemctl enable qemu-guest-agent",
      "sudo systemctl enable cloud-init",
      "sudo passwd -l ubuntu",
      "sudo truncate -s 0 /home/ubuntu/.ssh/authorized_keys",
      "sudo apt-get clean",
      "sudo cloud-init clean --logs --seed --machine-id",
    ]
  }
}
