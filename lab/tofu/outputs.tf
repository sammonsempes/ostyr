output "vms" {
  value = join("\n", [for name, vm in local.vms : "${name} ${vm.ssh_user} ${try(libvirt_domain.vm[name].network_interface[0].addresses[0], "")}"])
}
