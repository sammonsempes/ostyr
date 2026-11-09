locals {
  profile = yamldecode(file(var.profile_file))
  vms     = { for vm in local.profile.vms : vm.name => vm }
  prefix  = "ostyr-${var.task_id}"
  windows = { for name, vm in local.vms : name => try(vm.guest, "linux") == "windows" }
  uefi    = { for name, vm in local.vms : name => try(vm.firmware, "bios") == "uefi" }
}

resource "libvirt_network" "lab" {
  name      = local.prefix
  mode      = "none"
  addresses = ["192.168.${var.subnet_octet}.0/24"]
  autostart = false

  dhcp {
    enabled = true
  }

  xml {
    xslt = file("${path.module}/network-nodns.xsl")
  }
}

resource "libvirt_volume" "overlay" {
  for_each         = local.vms
  name             = "${local.prefix}-${each.key}.qcow2"
  pool             = var.pool
  format           = "qcow2"
  base_volume_name = each.value.base_image
  base_volume_pool = var.pool
  size             = try(each.value.disk_gb, 20) * 1073741824
}

resource "libvirt_cloudinit_disk" "init" {
  for_each  = local.vms
  name      = "${local.prefix}-${each.key}-init.iso"
  pool      = var.pool
  user_data = (local.windows[each.key] ?
    templatefile("${path.module}/user-data-windows.tftpl", { ssh_public_key = var.ssh_public_key }) :
  templatefile("${path.module}/user-data.tftpl", { hostname = each.key, ssh_user = each.value.ssh_user, ssh_public_key = var.ssh_public_key }))
  meta_data = local.windows[each.key] ? "instance-id: ${local.prefix}-${each.key}\nlocal-hostname: ${each.key}\n" : null
}

resource "libvirt_domain" "vm" {
  for_each  = local.vms
  name      = "${local.prefix}-${each.key}"
  memory    = try(each.value.memory_gb, 4) * 1024
  vcpu      = each.value.vcpu
  type      = var.domain_type
  cloudinit = libvirt_cloudinit_disk.init[each.key].id
  machine   = local.uefi[each.key] ? "q35" : null
  firmware  = local.uefi[each.key] ? "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd" : null

  dynamic "nvram" {
    for_each = local.uefi[each.key] ? [1] : []
    content {
      file     = "/var/lib/libvirt/qemu/nvram/${local.prefix}-${each.key}_VARS.fd"
      template = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
    }
  }

  dynamic "tpm" {
    for_each = try(each.value.tpm, false) ? [1] : []
    content {
      backend_type    = "emulator"
      backend_version = "2.0"
    }
  }

  cpu {
    mode = var.domain_type == "kvm" ? "host-passthrough" : "custom"
  }

  disk {
    file = libvirt_volume.overlay[each.key].id
  }

  network_interface {
    network_id     = libvirt_network.lab.id
    wait_for_lease = true
  }

  graphics {
    type        = "vnc"
    listen_type = "none"
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  xml {
    xslt = templatefile("${path.module}/metadata.xsl.tftpl", { task_id = var.task_id, created_at = var.created_at, secure_boot = local.uefi[each.key], tcg = var.domain_type == "qemu" })
  }
}
