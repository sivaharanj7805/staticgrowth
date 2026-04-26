variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
  default     = "rg-ai-sentinel"
}

variable "location" {
  description = "Azure region to deploy into"
  type        = string
  default     = "East US"
}

variable "vm_size" {
  description = "Azure VM size"
  type        = string
  default     = "Standard_B2s"
}

variable "admin_username" {
  description = "Admin username for the VM (SSH disabled publicly, used internally only)"
  type        = string
  default     = "azureuser"
}

variable "openai_api_key" {
  description = "OpenAI API key for vulnerability prioritization"
  type        = string
  sensitive   = true
}

variable "openai_model" {
  description = "OpenAI model to use for prioritization"
  type        = string
  default     = "gpt-4o"
}

variable "allowed_ip" {
  description = "Your IP address to allow API access (CIDR, e.g. 203.0.113.10/32). Set to * for any."
  type        = string
  default     = "*"
}
