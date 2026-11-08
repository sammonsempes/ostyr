variable "task_id" {
  type = string
}

variable "profile_file" {
  type = string
}

variable "pool" {
  type = string
}

variable "subnet_octet" {
  type = number
}

variable "ssh_public_key" {
  type = string
}

variable "created_at" {
  type = number
}

variable "domain_type" {
  type    = string
  default = "kvm"

  validation {
    condition     = contains(["kvm", "qemu"], var.domain_type)
    error_message = "domain_type must be kvm or qemu"
  }
}
