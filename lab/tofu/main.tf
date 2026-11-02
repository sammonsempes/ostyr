locals {
  profile = yamldecode(file(var.profile_file))
  vms     = { for vm in local.profile.vms : vm.name => vm }
  prefix  = "ostyr-${var.task_id}"
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
  size             = var.overlay_size_bytes
}

resource "libvirt_cloudinit_disk" "init" {
  for_each  = local.vms
  name      = "${local.prefix}-${each.key}-init.iso"
  pool      = var.pool
  user_data = templatefile("${path.module}/user-data.tftpl", { hostname = each.key, ssh_user = each.value.ssh_user, ssh_public_key = var.ssh_public_key })
}

resource "libvirt_domain" "vm" {
  for_each  = local.vms
  name      = "${local.prefix}-${each.key}"
  memory    = var.memory_mb
  vcpu      = each.value.vcpu
  cloudinit = libvirt_cloudinit_disk.init[each.key].id

  cpu {
    mode = "host-passthrough"
  }

  disk {
    file = libvirt_volume.overlay[each.key].id
  }

  network_interface {
    network_id     = libvirt_network.lab.id
    wait_for_lease = true
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  xml {
    xslt = templatefile("${path.module}/metadata.xsl.tftpl", { task_id = var.task_id, created_at = var.created_at })
  }
}
