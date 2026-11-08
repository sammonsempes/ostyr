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
  default = "output/ws2022-dc"
}

variable "ssh_public_key" {
  type        = string
  description = "Throwaway public key authorised for the build only"
}

variable "ssh_private_key_file" {
  type        = string
  description = "Private key matching ssh_public_key"
}

variable "iso_path" {
  type        = string
  default     = "/nonexistent/ws2022-dc.iso"
  description = "Local evaluation ISO, already verified by build.sh against its pin"
}

variable "image_checksum" {
  type        = string
  default     = "none"
  description = "build.sh passes the pinned sha256"
}

variable "drivers_dir" {
  type        = string
  default     = "/nonexistent/drivers"
  description = "Directory holding the viostor and NetKVM folders extracted from the virtio-win ISO"
}

variable "cloudbase_msi" {
  type    = string
  default = "/nonexistent/cloudbase-init.msi"
}

variable "build_password" {
  type      = string
  default   = "unused-in-validate"
  sensitive = true
}

locals {
  driver_paths = [for letter in ["D", "E", "F", "G", "H"] : "${letter}:\\viostor\\2k22\\amd64"]
  net_paths    = [for letter in ["D", "E", "F", "G", "H"] : "${letter}:\\NetKVM\\2k22\\amd64"]
}

source "qemu" "ws2022" {
  iso_url           = var.iso_path
  iso_checksum      = var.image_checksum
  disk_size         = "50G"
  disk_interface    = "virtio"
  disk_compression  = true
  format            = "qcow2"
  net_device        = "virtio-net"
  accelerator       = var.accelerator
  machine_type      = "q35"
  efi_boot          = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
  headless          = true
  memory            = 4096
  cpus              = 4
  qemuargs          = [["-cpu", "host"]]
  output_directory  = var.output_directory
  vm_name           = "ws2022-dc.qcow2"
  cd_label          = "ANSWER"
  cd_files          = ["${var.drivers_dir}/viostor", "${var.drivers_dir}/NetKVM"]
  cd_content = {
    "Autounattend.xml" = templatefile("${path.root}/windows/autounattend.xml.pkrtpl", {
      image_index    = 2
      driver_paths   = concat(local.driver_paths, local.net_paths)
      build_password = var.build_password
    })
    "bootstrap.ps1" = templatefile("${path.root}/windows/bootstrap.ps1.pkrtpl", { ssh_public_key = var.ssh_public_key })
  }
  boot_wait            = "1s"
  boot_command         = ["<spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar>"]
  communicator         = "ssh"
  ssh_username         = "packer"
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "${90 * var.timeout_factor}m"
  shutdown_command     = "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\finalize.ps1"
  shutdown_timeout     = "30m"
}

build {
  sources = ["source.qemu.ws2022"]

  provisioner "file" {
    source      = var.cloudbase_msi
    destination = "C:/Windows/Temp/cloudbase-init.msi"
  }

  provisioner "file" {
    source      = "${path.root}/windows/cloudbase-init.conf"
    destination = "C:/Windows/Temp/cloudbase-init.conf"
  }

  provisioner "file" {
    source      = "${path.root}/windows/finalize.ps1"
    destination = "C:/Windows/Temp/finalize.ps1"
  }

  provisioner "powershell" {
    script           = "${path.root}/windows/provision.ps1"
    environment_vars = ["OSTYR_IMAGE=ws2022-dc"]
  }
}
